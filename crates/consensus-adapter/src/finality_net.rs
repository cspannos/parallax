//! Serving finality certificates (ADR 0031). Each validator answers two
//! requests on a plain TCP port:
//!
//! - `GET h`: the certificate it holds for height `h` (empty if none).
//! - `RECOLLECT h r`: re-send its own finality signature for `h` to the
//!   collectors of failover round `r`. A consumer uses this when the
//!   collectors announced a certificate but nobody serves one.
//!
//! Plaintext on purpose: a certificate is self-authenticating (verified
//! against the roster), and a recollect only makes a validator re-send a
//! signature it already sent.
//!
//! Limits: connections per source IP and at once ([`Limits::CERT_SERVER`]),
//! a deadline per request, and a server-wide budget for `RECOLLECT` (each one
//! makes this validator send ~3.4 KB to k collectors).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use commitments::Digest;
use crypto_suite::{SuitePolicy, SuitePublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::finality::{max_rounds, FinalityCertificate};
use crate::limits::{Admission, Limits, TokenBucket, HANDSHAKE_WAIT};

const REQ_GET: u8 = 0;
const REQ_RECOLLECT: u8 = 1;
const MAX_CERT: usize = 4 << 20;
const IO_WAIT: Duration = Duration::from_millis(500);
/// Server-wide `RECOLLECT` budget: burst, then per second.
const RECOLLECT_BURST: f64 = 32.0;
const RECOLLECT_PER_SEC: f64 = 16.0;

/// Certificates a collector serves.
pub type CertStore = Arc<Mutex<BTreeMap<u64, FinalityCertificate>>>;

/// Port after the consensus and intent-gossip ports.
pub fn cert_addr(base_port: usize, n: usize, index: usize) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], (base_port + 2 * n + index) as u16))
}

/// `serve = false` withholds every certificate (a test knob for a collector
/// that announces but does not serve).
pub fn spawn_cert_server(
    bind: SocketAddr,
    store: CertStore,
    recollect: mpsc::UnboundedSender<(u64, u32)>,
    serve: bool,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(bind).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(%bind, "cert server bind: {e}");
                return;
            }
        };
        let gate = Admission::new(Limits::CERT_SERVER);
        let budget = Arc::new(Mutex::new(TokenBucket::full(RECOLLECT_BURST)));
        while let Ok((mut stream, peer)) = listener.accept().await {
            let Some(permit) = gate.admit(peer.ip()) else {
                continue; // dropping the stream closes it
            };
            let store = store.clone();
            let recollect = recollect.clone();
            let budget = budget.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let mut req = [0u8; 13];
                match tokio::time::timeout(HANDSHAKE_WAIT, stream.read_exact(&mut req)).await {
                    Ok(Ok(_)) => {}
                    _ => return,
                }
                let height = u64::from_le_bytes(req[1..9].try_into().unwrap());
                let body = match req[0] {
                    REQ_GET if serve => store.lock().unwrap().get(&height).map(|c| c.encode()).unwrap_or_default(),
                    REQ_RECOLLECT => {
                        let round = u32::from_le_bytes(req[9..13].try_into().unwrap());
                        if budget.lock().unwrap().take(RECOLLECT_BURST, RECOLLECT_PER_SEC) {
                            let _ = recollect.send((height, round));
                        } else {
                            tracing::debug!(height, round, "recollect over budget; dropped");
                        }
                        Vec::new()
                    }
                    _ => Vec::new(),
                };
                let reply = async {
                    stream.write_all(&(body.len() as u32).to_le_bytes()).await?;
                    stream.write_all(&body).await
                };
                let _ = tokio::time::timeout(HANDSHAKE_WAIT, reply).await;
            });
        }
    })
}

async fn request(addr: SocketAddr, tag: u8, height: u64, round: u32) -> Option<Vec<u8>> {
    let io = async {
        let mut s = TcpStream::connect(addr).await.ok()?;
        let mut req = vec![tag];
        req.extend_from_slice(&height.to_le_bytes());
        req.extend_from_slice(&round.to_le_bytes());
        s.write_all(&req).await.ok()?;
        let mut lenb = [0u8; 4];
        s.read_exact(&mut lenb).await.ok()?;
        let len = u32::from_le_bytes(lenb) as usize;
        if len > MAX_CERT {
            return None;
        }
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).await.ok()?;
        Some(body)
    };
    tokio::time::timeout(IO_WAIT, io).await.ok().flatten()
}

/// First certificate from `addrs` that verifies and is on `value_id` at
/// `height`. Bytes downloaded are returned too.
pub async fn fetch_certificate(
    addrs: &[SocketAddr],
    height: u64,
    value_id: Digest,
    policy: SuitePolicy,
    roster: &[SuitePublicKey],
) -> (Option<FinalityCertificate>, u64) {
    let mut bytes = 0u64;
    for &addr in addrs {
        let Some(body) = request(addr, REQ_GET, height, 0).await else {
            continue;
        };
        bytes += body.len() as u64;
        if let Some(cert) = FinalityCertificate::decode(&body) {
            if cert.height == height && cert.value_id == value_id && cert.verify(policy, roster).is_ok() {
                return (Some(cert), bytes);
            }
        }
    }
    (None, bytes)
}

/// Ask every validator to re-send its signature for `height` to round `round`.
pub async fn request_recollect(addrs: &[SocketAddr], height: u64, round: u32) {
    for &addr in addrs {
        let _ = request(addr, REQ_RECOLLECT, height, round).await;
    }
}

#[derive(Clone, Debug)]
pub struct Obtained {
    pub cert: FinalityCertificate,
    /// Failover rounds the consumer had to request (0 = served first try).
    pub recollects: u32,
    pub bytes: u64,
    pub elapsed: Duration,
}

/// Consumer side: fetch a verified certificate; if none appears within
/// `wait`, request the next failover round and try again, until every
/// validator has been a collector once or `deadline` passes.
#[allow(clippy::too_many_arguments)]
pub async fn obtain_certificate(
    addrs: &[SocketAddr],
    height: u64,
    value_id: Digest,
    policy: SuitePolicy,
    roster: &[SuitePublicKey],
    k: usize,
    wait: Duration,
    deadline: Duration,
) -> Option<Obtained> {
    let t0 = Instant::now();
    let mut round = 0u32;
    let mut bytes = 0;
    loop {
        let t_round = Instant::now();
        while t_round.elapsed() < wait {
            let (cert, b) = fetch_certificate(addrs, height, value_id, policy, roster).await;
            bytes += b;
            if let Some(cert) = cert {
                return Some(Obtained { cert, recollects: round, bytes, elapsed: t0.elapsed() });
            }
            if t0.elapsed() > deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        round += 1;
        if round >= max_rounds(addrs.len(), k) {
            round = 1; // wrap: collectors may have recovered
        }
        request_recollect(addrs, height, round).await;
    }
}
