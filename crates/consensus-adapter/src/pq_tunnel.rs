//! Post-quantum tunnel under Malachite's libp2p (ADR 0034).
//!
//! Malachite's transport is libp2p TCP + Noise (X25519, Ed25519 identity):
//! classical, so its traffic is open to harvest-now-decrypt-later. Rather
//! than fork libp2p, each validator wraps the TCP connections:
//!
//! ```text
//! Malachite i ──tcp──▶ forward(i→j) ══ suite handshake + AEAD ══▶ tunnel j ──tcp──▶ Malachite j
//!                      (loopback)          (the network)                 (loopback)
//! ```
//!
//! The tunnel is `crypto_suite::kex` (X25519 + ML-KEM-768, transcript signed
//! by both validators' suite keys, peers checked against the validator set),
//! then XChaCha20-Poly1305 frames. libp2p's Noise still runs inside, so a
//! recorded session needs **both** the hybrid tunnel and Noise broken.
//! Malachite only dials its configured forward ports (discovery is off).
//! `persistent_peers_only` cannot be used: inbound tunnel connections arrive
//! from loopback, not from a configured peer address.

use std::net::SocketAddr;

use crypto_suite::kex::{self, Half};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::intent_gossip::GossipSecurity;
use crate::limits::{Admission, Limits, HANDSHAKE_WAIT};

const CHUNK: usize = 16 * 1024;

static SESSIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static REJECTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Process-wide `(tunnels established, handshakes rejected)` (tests, benches).
pub fn tunnel_stats() -> (u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (SESSIONS.load(Relaxed), REJECTED.load(Relaxed))
}

fn count(ok: bool) {
    use std::sync::atomic::Ordering::Relaxed;
    if ok { &SESSIONS } else { &REJECTED }.fetch_add(1, Relaxed);
}
const MAX_FRAME: usize = CHUNK + kex::TAG_BYTES;

/// Port layout after consensus (`base + i`), intent gossip (`base + n + i`)
/// and cert servers (`base + 2n + i`).
pub fn tunnel_addr(base_port: usize, n: usize, index: usize) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], (base_port + 3 * n + index) as u16))
}

/// Where Malachite `i` dials peer `j` (a local forwarder).
pub fn forward_port(base_port: usize, n: usize, i: usize, j: usize) -> usize {
    base_port + 4 * n + i * n + j
}

async fn write_msg(s: &mut TcpStream, m: &[u8]) -> std::io::Result<()> {
    s.write_all(&(m.len() as u32).to_le_bytes()).await?;
    s.write_all(m).await
}

async fn read_msg(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut l = [0u8; 4];
    s.read_exact(&mut l).await?;
    let n = u32::from_le_bytes(l) as usize;
    if n > (1 << 20) {
        return Err(std::io::Error::other("handshake message too long"));
    }
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).await?;
    Ok(b)
}

fn other(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Plain → sealed frames.
async fn seal_pump(mut plain: OwnedReadHalf, mut wire: OwnedWriteHalf, mut half: Half) {
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match plain.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let ct = half.seal(&buf[..n]);
        if wire.write_all(&(ct.len() as u32).to_le_bytes()).await.is_err() || wire.write_all(&ct).await.is_err() {
            break;
        }
    }
    let _ = wire.shutdown().await;
}

/// Sealed frames → plain. Any frame that fails to open ends the connection.
async fn open_pump(mut wire: OwnedReadHalf, mut plain: OwnedWriteHalf, mut half: Half) {
    let mut l = [0u8; 4];
    loop {
        if wire.read_exact(&mut l).await.is_err() {
            break;
        }
        let n = u32::from_le_bytes(l) as usize;
        if n > MAX_FRAME {
            break;
        }
        let mut ct = vec![0u8; n];
        if wire.read_exact(&mut ct).await.is_err() {
            break;
        }
        let Ok(pt) = half.open(&ct) else {
            tracing::warn!("pq tunnel: frame failed to open; closing");
            break;
        };
        if plain.write_all(&pt).await.is_err() {
            break;
        }
    }
    let _ = plain.shutdown().await;
}

fn pump(plain: TcpStream, wire: TcpStream, session: kex::Session) {
    let (pr, pw) = plain.into_split();
    let (wr, ww) = wire.into_split();
    tokio::spawn(seal_pump(pr, ww, session.send));
    tokio::spawn(open_pump(wr, pw, session.recv));
}

/// Inbound side: accept tunnels, authenticate, forward into local Malachite.
pub fn spawn_tunnel_listener(bind: SocketAddr, local: SocketAddr, sec: GossipSecurity) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(bind).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(%bind, "pq tunnel bind: {e}");
                return;
            }
        };
        let gate = Admission::new(Limits::HANDSHAKE);
        while let Ok((mut wire, peer)) = listener.accept().await {
            let Some(permit) = gate.admit(peer.ip()) else {
                tracing::warn!(%bind, %peer, "pq tunnel handshake over limit; refused");
                continue;
            };
            let sec = sec.clone();
            tokio::spawn(async move {
                let hs = async {
                    let hello = read_msg(&mut wire).await?;
                    let (hs, reply) = kex::respond(sec.policy, &sec.key, &hello).map_err(other)?;
                    write_msg(&mut wire, &reply).await?;
                    let fin = read_msg(&mut wire).await?;
                    let (session, peer) = hs.finish(&fin).map_err(other)?;
                    if !sec.peers.contains(&peer) {
                        return Err(other("initiator is not a validator"));
                    }
                    Ok(session)
                };
                let res: std::io::Result<kex::Session> = tokio::time::timeout(HANDSHAKE_WAIT, hs)
                    .await
                    .unwrap_or_else(|_| Err(other("handshake timed out")));
                drop(permit);
                count(res.is_ok());
                match res {
                    Ok(session) => match TcpStream::connect(local).await {
                        Ok(plain) => {
                            let _ = plain.set_nodelay(true);
                            let _ = wire.set_nodelay(true);
                            pump(plain, wire, session);
                        }
                        Err(e) => tracing::warn!("pq tunnel: local connect {local}: {e}"),
                    },
                    Err(e) => tracing::warn!(%bind, "pq tunnel handshake rejected: {e}"),
                }
            });
        }
    })
}

/// Outbound side: Malachite dials `bind` (loopback); each connection becomes
/// a tunnel to `remote`.
pub fn spawn_forwarder(bind: SocketAddr, remote: SocketAddr, sec: GossipSecurity) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(bind).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(%bind, "pq forwarder bind: {e}");
                return;
            }
        };
        while let Ok((plain, _)) = listener.accept().await {
            let sec = sec.clone();
            tokio::spawn(async move {
                let res: std::io::Result<(TcpStream, kex::Session)> = async {
                    let mut wire = TcpStream::connect(remote).await?;
                    let (hs, hello) = kex::ClientHandshake::start(sec.key.suite());
                    write_msg(&mut wire, &hello).await?;
                    let reply = read_msg(&mut wire).await?;
                    let (session, fin, peer) = hs.finish(sec.policy, &sec.key, &reply).map_err(other)?;
                    if !sec.peers.contains(&peer) {
                        return Err(other("responder is not a validator"));
                    }
                    write_msg(&mut wire, &fin).await?;
                    Ok((wire, session))
                }
                .await;
                match res {
                    Ok((wire, session)) => {
                        let _ = plain.set_nodelay(true);
                        let _ = wire.set_nodelay(true);
                        pump(plain, wire, session);
                    }
                    Err(e) => tracing::warn!(%remote, "pq tunnel dial failed: {e}"),
                }
            });
        }
    })
}
