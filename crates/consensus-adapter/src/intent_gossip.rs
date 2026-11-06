//! Localhost TCP fan-out of canonical [`Input`] and `SetAck` (ADR 0017 / 0021).
//!
//! Not Malachite `NetworkMsg` (that is proposal parts only). Not WAN. Not FOCIL.
//!
//! With [`GossipSecurity`] (ADR 0030) each connection starts with a
//! suite-tagged handshake (`crypto_suite::kex`: X25519, plus ML-KEM-768 when
//! hybrid; transcript signed by validator keys) and every frame is sealed with
//! XChaCha20-Poly1305. Without it, frames are plaintext as before.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use commitments::Digest;
use crypto_suite::kex::{self, Half};
use crypto_suite::{SuitePolicy, SuitePublicKey, SuiteSigningKey};

use crate::finality::FinalitySig;
use crate::limits::{Admission, Limits, HANDSHAKE_WAIT};
use crate::order_auth::{check_order, OrderAuth};
use protocol_types::{CanonicalDecode, CanonicalEncode, Input};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

const MAX_FRAME: usize = 1_048_576;
/// Signed intents queued for verification per connection (backpressure).
const VERIFY_IN_FLIGHT: usize = 4096;
/// Largest batch verified at once.
const VERIFY_BATCH: usize = 512;

/// Verify a batch's intents on all cores; keep order; drop invalid ones.
fn verify_frames(policy: SuitePolicy, batch: Vec<GossipFrame>) -> Vec<GossipFrame> {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let chunk = batch.len().div_ceil(threads).max(1);
    let ok: Vec<bool> = std::thread::scope(|sc| {
        let parts: Vec<_> = batch
            .chunks(chunk)
            .map(|c| {
                sc.spawn(move || {
                    c.iter()
                        .map(|f| match f {
                            GossipFrame::Intent { input, auth, .. } => check_order(policy, input, auth.as_ref()).is_ok(),
                            _ => true,
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        parts.into_iter().flat_map(|p| p.join().expect("verify thread")).collect()
    });
    batch.into_iter().zip(ok).filter_map(|(f, ok)| ok.then_some(f)).collect()
}
const CONNECT_TRIES: u32 = 40;
const CONNECT_WAIT: Duration = Duration::from_millis(50);

pub const FRAME_INTENT: u8 = 0;
pub const FRAME_SET_ACK: u8 = 1;
pub const FRAME_FINALITY: u8 = 2;
pub const FRAME_CERTIFIED: u8 = 3;
pub const FRAME_SIGNED_INTENT: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetAck {
    pub voter: [u8; 20],
    pub set_id: Digest,
    pub count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GossipFrame {
    /// An intent and its target height (ADR 0027), with the owner's
    /// signature when orders are signed (ADR 0033).
    Intent { height: u64, input: Input, auth: Option<OrderAuth> },
    SetAck(SetAck),
    /// Hybrid finality signature, sent to collectors only (ADR 0031).
    Finality(FinalitySig),
    /// A collector holds a certificate for this height (stops failover).
    Certified { height: u64 },
}

/// Encrypted, authenticated gossip channel (ADR 0030).
#[derive(Clone, Debug)]
pub struct GossipSecurity {
    /// This node's validator key; its suite is the suite it offers.
    pub key: SuiteSigningKey,
    /// Weakest suite accepted for the handshake and its signatures.
    pub policy: SuitePolicy,
    /// Keys allowed on the other end (the validator set).
    pub peers: Arc<Vec<SuitePublicKey>>,
}

pub fn intent_addr(base_port: usize, n: usize, index: usize) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], (base_port + n + index) as u16))
}

#[cfg(test)]
pub fn spawn_listener(
    bind: SocketAddr,
    tx: mpsc::UnboundedSender<GossipFrame>,
    security: Option<GossipSecurity>,
) -> JoinHandle<()> {
    spawn_listener_with(bind, tx, security, None)
}

/// With `orders`, every account intent must carry a valid owner signature
/// under that policy; others are dropped here, before the app sees them.
/// Verification runs on the per-connection task, so peers verify in parallel.
pub fn spawn_listener_with(
    bind: SocketAddr,
    tx: mpsc::UnboundedSender<GossipFrame>,
    security: Option<GossipSecurity>,
    orders: Option<SuitePolicy>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(bind).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(%bind, "intent gossip bind: {e}");
                return;
            }
        };
        let gate = Admission::new(Limits::HANDSHAKE);
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            // Only secured gossip pays for an unauthenticated handshake.
            let permit = match &security {
                None => None,
                Some(_) => match gate.admit(peer.ip()) {
                    Some(p) => Some(p),
                    None => {
                        tracing::warn!(%bind, %peer, "intent gossip handshake over limit; refused");
                        continue;
                    }
                },
            };
            let tx = tx.clone();
            let security = security.clone();
            tokio::spawn(async move {
                let mut stream = stream;
                let mut open = match &security {
                    None => None,
                    Some(sec) => match tokio::time::timeout(HANDSHAKE_WAIT, accept_handshake(&mut stream, sec)).await {
                        Ok(Ok(half)) => Some(half),
                        Ok(Err(e)) => {
                            tracing::warn!(%bind, "intent gossip handshake rejected: {e}");
                            return;
                        }
                        Err(_) => {
                            tracing::warn!(%bind, "intent gossip handshake timed out");
                            return;
                        }
                    },
                };
                drop(permit);
                let Some(policy) = orders else {
                    while let Ok(frame) = read_frame(&mut stream, open.as_mut()).await {
                        if tx.send(frame).is_err() {
                            break;
                        }
                    }
                    return;
                };
                // Signed orders: a verifier task drains whatever has arrived
                // (up to VERIFY_BATCH frames), checks the batch on all cores,
                // and forwards it in arrival order, so an ACK never overtakes
                // the intents it covers.
                let (raw_tx, mut raw_rx) = mpsc::channel::<GossipFrame>(VERIFY_IN_FLIGHT);
                let verifier = tokio::spawn(async move {
                    while let Some(first) = raw_rx.recv().await {
                        let mut batch = vec![first];
                        while batch.len() < VERIFY_BATCH {
                            match raw_rx.try_recv() {
                                Ok(f) => batch.push(f),
                                Err(_) => break,
                            }
                        }
                        let Ok(ok) = tokio::task::spawn_blocking(move || verify_frames(policy, batch)).await else {
                            break;
                        };
                        for f in ok {
                            if tx.send(f).is_err() {
                                return;
                            }
                        }
                    }
                });
                while let Ok(frame) = read_frame(&mut stream, open.as_mut()).await {
                    if raw_tx.send(frame).await.is_err() {
                        break;
                    }
                }
                drop(raw_tx);
                let _ = verifier.await;
            });
        }
    })
}

/// A connected peer; `seal` is set on secured channels.
struct Conn {
    stream: TcpStream,
    seal: Option<Half>,
}

pub struct IntentPublisher {
    peers: Vec<SocketAddr>,
    streams: Vec<Option<Conn>>,
    security: Option<GossipSecurity>,
}

impl IntentPublisher {
    pub fn with_security(peers: Vec<SocketAddr>, security: Option<GossipSecurity>) -> Self {
        let streams = (0..peers.len()).map(|_| None).collect();
        Self { peers, streams, security }
    }

    /// Publish `(target height, intent)` pairs.
    #[cfg(test)]
    pub async fn publish(&mut self, inputs: &[(u64, Input)]) -> u64 {
        self.publish_signed(inputs, |_| None).await
    }

    /// Publish intents with their owner signatures where `auth` has one.
    pub async fn publish_signed<'a>(
        &mut self,
        inputs: &[(u64, Input)],
        auth: impl Fn(&Input) -> Option<&'a OrderAuth>,
    ) -> u64 {
        if inputs.is_empty() {
            return 0;
        }
        self.connect_all().await;
        let frames: Vec<Vec<u8>> = inputs
            .iter()
            .map(|(h, i)| match auth(i) {
                Some(a) => encode_signed_intent(*h, i, a),
                None => encode_intent(*h, i),
            })
            .collect();
        let bytes = frames.iter().map(|f| f.len() as u64).sum();
        self.write_frames(Arc::new(frames)).await;
        bytes
    }

    pub async fn publish_ack(&mut self, ack: SetAck) {
        self.connect_all().await;
        let frames = Arc::new(vec![encode_ack(&ack)]);
        self.write_frames(frames).await;
    }

    /// Send a finality signature to the given peer slots (indices into the
    /// `peers` list); returns bytes written per peer.
    pub async fn publish_finality(&mut self, slots: &[usize], fs: &FinalitySig) -> u64 {
        if slots.is_empty() {
            return 0;
        }
        self.connect_all().await;
        let body = fs.encode();
        let mut frame = Vec::with_capacity(5 + body.len());
        frame.extend_from_slice(&((1 + body.len()) as u32).to_le_bytes());
        frame.push(FRAME_FINALITY);
        frame.extend_from_slice(&body);
        let len = frame.len() as u64;
        self.write_frames_to(Arc::new(vec![frame]), Some(slots)).await;
        len
    }

    /// Tell every peer this node holds a certificate for `height`.
    pub async fn publish_certified(&mut self, height: u64) {
        self.connect_all().await;
        let mut frame = 9u32.to_le_bytes().to_vec();
        frame.push(FRAME_CERTIFIED);
        frame.extend_from_slice(&height.to_le_bytes());
        self.write_frames(Arc::new(vec![frame])).await;
    }

    async fn write_frames(&mut self, frames: Arc<Vec<Vec<u8>>>) {
        self.write_frames_to(frames, None).await
    }

    async fn write_frames_to(&mut self, frames: Arc<Vec<Vec<u8>>>, only: Option<&[usize]>) {
        let mut set = JoinSet::new();
        for (i, slot) in self.streams.iter_mut().enumerate() {
            if only.is_some_and(|o| !o.contains(&i)) {
                continue;
            }
            let Some(conn) = slot.take() else {
                continue;
            };
            let frames = Arc::clone(&frames);
            set.spawn(async move {
                let mut conn = conn;
                let ok = write_encoded(&mut conn, &frames).await;
                (i, ok.then_some(conn))
            });
        }
        while let Some(joined) = set.join_next().await {
            if let Ok((i, stream)) = joined {
                self.streams[i] = stream;
            }
        }
    }

    pub async fn connect_all(&mut self) {
        let mut set = JoinSet::new();
        for (i, slot) in self.streams.iter_mut().enumerate() {
            if slot.is_some() {
                continue;
            }
            let addr = self.peers[i];
            let security = self.security.clone();
            set.spawn(async move {
                let Some(mut stream) = try_connect(addr).await else {
                    return (i, None);
                };
                let seal = match &security {
                    None => None,
                    Some(sec) => match connect_handshake(&mut stream, sec).await {
                        Ok(half) => Some(half),
                        Err(e) => {
                            tracing::warn!(%addr, "intent gossip handshake failed: {e}");
                            return (i, None);
                        }
                    },
                };
                (i, Some(Conn { stream, seal }))
            });
        }
        while let Some(joined) = set.join_next().await {
            if let Ok((i, Some(conn))) = joined {
                self.streams[i] = Some(conn);
            }
        }
    }
}

async fn write_msg(stream: &mut TcpStream, msg: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(msg.len() as u32).to_le_bytes()).await?;
    stream.write_all(msg).await?;
    stream.flush().await
}

async fn read_msg(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut lenb = [0u8; 4];
    stream.read_exact(&mut lenb).await.map_err(|e| e.to_string())?;
    let len = u32::from_le_bytes(lenb) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(format!("handshake message length {len}"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Initiator side; returns the sending half (gossip is one-way).
async fn connect_handshake(stream: &mut TcpStream, sec: &GossipSecurity) -> Result<Half, String> {
    let (hs, hello) = kex::ClientHandshake::start(sec.key.suite());
    write_msg(stream, &hello).await.map_err(|e| e.to_string())?;
    let reply = read_msg(stream).await?;
    let (session, finish, peer) = hs.finish(sec.policy, &sec.key, &reply).map_err(|e| e.to_string())?;
    if !sec.peers.contains(&peer) {
        return Err("responder is not a validator".into());
    }
    write_msg(stream, &finish).await.map_err(|e| e.to_string())?;
    Ok(session.send)
}

/// Responder side; returns the receiving half.
async fn accept_handshake(stream: &mut TcpStream, sec: &GossipSecurity) -> Result<Half, String> {
    let hello = read_msg(stream).await?;
    let (hs, reply) = kex::respond(sec.policy, &sec.key, &hello).map_err(|e| e.to_string())?;
    write_msg(stream, &reply).await.map_err(|e| e.to_string())?;
    let finish = read_msg(stream).await?;
    let (session, peer) = hs.finish(&finish).map_err(|e| e.to_string())?;
    if !sec.peers.contains(&peer) {
        return Err("initiator is not a validator".into());
    }
    Ok(session.recv)
}

async fn try_connect(addr: SocketAddr) -> Option<TcpStream> {
    for _ in 0..CONNECT_TRIES {
        match tokio::time::timeout(CONNECT_WAIT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Some(stream);
            }
            _ => {}
        }
    }
    None
}

/// `len ‖ FRAME_SIGNED_INTENT ‖ height ‖ u32 len ‖ input ‖ auth` (ADR 0033).
fn encode_signed_intent(height: u64, input: &Input, auth: &OrderAuth) -> Vec<u8> {
    let bytes = input.encode_vec();
    let a = auth.encode();
    let body = 1 + 8 + 4 + bytes.len() + a.len();
    let mut frame = Vec::with_capacity(4 + body);
    frame.extend_from_slice(&(body as u32).to_le_bytes());
    frame.push(FRAME_SIGNED_INTENT);
    frame.extend_from_slice(&height.to_le_bytes());
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(&bytes);
    frame.extend_from_slice(&a);
    frame
}

/// `len ‖ FRAME_INTENT ‖ target_height_le ‖ input` (ADR 0027).
fn encode_intent(height: u64, input: &Input) -> Vec<u8> {
    let bytes = input.encode_vec();
    let mut frame = Vec::with_capacity(13 + bytes.len());
    frame.extend_from_slice(&((9 + bytes.len()) as u32).to_le_bytes());
    frame.push(FRAME_INTENT);
    frame.extend_from_slice(&height.to_le_bytes());
    frame.extend_from_slice(&bytes);
    frame
}

fn encode_ack(ack: &SetAck) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + 20 + 32 + 4);
    body.push(FRAME_SET_ACK);
    body.extend_from_slice(&ack.voter);
    body.extend_from_slice(&ack.set_id.0);
    body.extend_from_slice(&ack.count.to_le_bytes());
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// Plaintext frames go as encoded; sealed frames are `len ‖ seal(body)`.
async fn write_encoded(conn: &mut Conn, frames: &[Vec<u8>]) -> bool {
    for frame in frames {
        let ok = match conn.seal.as_mut() {
            None => conn.stream.write_all(frame).await,
            Some(half) => {
                let ct = half.seal(&frame[4..]);
                let mut out = Vec::with_capacity(4 + ct.len());
                out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
                out.extend_from_slice(&ct);
                conn.stream.write_all(&out).await
            }
        };
        if ok.is_err() {
            return false;
        }
    }
    conn.stream.flush().await.is_ok()
}

async fn read_frame(stream: &mut TcpStream, open: Option<&mut Half>) -> Result<GossipFrame, ()> {
    let mut lenb = [0u8; 4];
    stream.read_exact(&mut lenb).await.map_err(|_| ())?;
    let len = u32::from_le_bytes(lenb) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(());
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.map_err(|_| ())?;
    match open {
        None => decode_frame(&buf),
        Some(half) => decode_frame(&half.open(&buf).map_err(|_| ())?),
    }
}

fn decode_frame(buf: &[u8]) -> Result<GossipFrame, ()> {
    let tag = *buf.first().ok_or(())?;
    let rest = &buf[1..];
    match tag {
        FRAME_INTENT => {
            let (h, body) = rest.split_at_checked(8).ok_or(())?;
            Ok(GossipFrame::Intent {
                height: u64::from_le_bytes(h.try_into().map_err(|_| ())?),
                input: Input::decode_slice(body).map_err(|_| ())?,
                auth: None,
            })
        }
        FRAME_SIGNED_INTENT => {
            let (h, rest) = rest.split_at_checked(8).ok_or(())?;
            let (n, rest) = rest.split_at_checked(4).ok_or(())?;
            let n = u32::from_le_bytes(n.try_into().map_err(|_| ())?) as usize;
            let (body, rest) = rest.split_at_checked(n).ok_or(())?;
            let (auth, used) = OrderAuth::decode(rest).ok_or(())?;
            if used != rest.len() {
                return Err(());
            }
            Ok(GossipFrame::Intent {
                height: u64::from_le_bytes(h.try_into().map_err(|_| ())?),
                input: Input::decode_slice(body).map_err(|_| ())?,
                auth: Some(auth),
            })
        }
        FRAME_SET_ACK => {
            if rest.len() != 20 + 32 + 4 {
                return Err(());
            }
            let mut voter = [0u8; 20];
            voter.copy_from_slice(&rest[..20]);
            let mut id = [0u8; 32];
            id.copy_from_slice(&rest[20..52]);
            let count = u32::from_le_bytes(rest[52..56].try_into().map_err(|_| ())?);
            Ok(GossipFrame::SetAck(SetAck {
                voter,
                set_id: Digest(id),
                count,
            }))
        }
        FRAME_FINALITY => FinalitySig::decode(rest).map(GossipFrame::Finality).ok_or(()),
        FRAME_CERTIFIED => Ok(GossipFrame::Certified {
            height: u64::from_le_bytes(rest.try_into().map_err(|_| ())?),
        }),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clob::testutil::limit;
    use protocol_types::{CryptoSuiteId, Side};

    #[tokio::test]
    async fn localhost_frame_roundtrip() {
        let bind = intent_addr(51000 + (std::process::id() as usize % 1000), 2, 0);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let listen = spawn_listener(bind, tx, None);
        let mut puber = IntentPublisher::with_security(vec![bind], None);
        let input = Input::Place(limit(1, 1, Side::Buy, 1, 10, 1));
        puber.publish(&[(7, input.clone())]).await;
        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert_eq!(got, GossipFrame::Intent { height: 7, input, auth: None });
        listen.abort();
    }

    fn security(suite: CryptoSuiteId, min: CryptoSuiteId, seed: u8, peers: &[&SuiteSigningKey]) -> GossipSecurity {
        GossipSecurity {
            key: SuiteSigningKey::from_seed(suite, [seed; 32]),
            policy: SuitePolicy { min },
            peers: Arc::new(peers.iter().map(|k| k.public()).collect()),
        }
    }

    async fn secured_delivery(listen_sec: GossipSecurity, pub_sec: GossipSecurity, port: usize) -> Option<GossipFrame> {
        let bind = intent_addr(port + (std::process::id() as usize % 1000), 2, 0);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let listen = spawn_listener(bind, tx, Some(listen_sec));
        let mut puber = IntentPublisher::with_security(vec![bind], Some(pub_sec));
        let input = Input::Place(limit(1, 1, Side::Buy, 1, 10, 1));
        puber.publish(&[(7, input)]).await;
        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.ok().flatten();
        listen.abort();
        got
    }

    #[tokio::test]
    async fn hybrid_secured_roundtrip() {
        use CryptoSuiteId::HybridV1;
        let a = SuiteSigningKey::from_seed(HybridV1, [1; 32]);
        let b = SuiteSigningKey::from_seed(HybridV1, [2; 32]);
        let got = secured_delivery(
            security(HybridV1, HybridV1, 1, &[&b]),
            security(HybridV1, HybridV1, 2, &[&a]),
            53000,
        )
        .await;
        let input = Input::Place(limit(1, 1, Side::Buy, 1, 10, 1));
        assert_eq!(got, Some(GossipFrame::Intent { height: 7, input, auth: None }));
    }

    /// A classical publisher cannot reach a hybrid-policy listener.
    #[tokio::test]
    async fn hybrid_listener_rejects_classical_publisher() {
        use CryptoSuiteId::{ClassicalV0, HybridV1};
        let a = SuiteSigningKey::from_seed(HybridV1, [1; 32]);
        let b = SuiteSigningKey::from_seed(ClassicalV0, [2; 32]);
        let got = secured_delivery(
            security(HybridV1, HybridV1, 1, &[&b]),
            security(ClassicalV0, ClassicalV0, 2, &[&a]),
            54000,
        )
        .await;
        assert_eq!(got, None);
    }

    /// A key outside the validator set is refused even with the right suite.
    #[tokio::test]
    async fn secured_listener_rejects_unknown_key() {
        use CryptoSuiteId::HybridV1;
        let a = SuiteSigningKey::from_seed(HybridV1, [1; 32]);
        let other = SuiteSigningKey::from_seed(HybridV1, [9; 32]);
        let got = secured_delivery(
            security(HybridV1, HybridV1, 1, &[&other]),
            security(HybridV1, HybridV1, 2, &[&a]),
            55000,
        )
        .await;
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn localhost_ack_roundtrip() {
        let bind = intent_addr(52000 + (std::process::id() as usize % 1000), 2, 0);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let listen = spawn_listener(bind, tx, None);
        let mut puber = IntentPublisher::with_security(vec![bind], None);
        let ack = SetAck {
            voter: [7u8; 20],
            set_id: Digest([9u8; 32]),
            count: 10,
        };
        puber.publish_ack(ack).await;
        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert_eq!(got, GossipFrame::SetAck(ack));
        listen.abort();
    }
}
