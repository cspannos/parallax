//! `EngineBuilder` wiring for N full-view validators (TCP or QUIC).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use clob::Genesis;
use eyre::Result;
use malachitebft_app_channel::app::config::NodeConfig;
use malachitebft_app_channel::app::types::Keypair;
use malachitebft_app_channel::{
    ConsensusContext, EngineBuilder, EngineHandle, NetworkContext, NetworkIdentity, RequestContext,
    SyncContext, WalContext,
};
use malachitebft_codec::Codec;
use malachitebft_config::{
    ConsensusConfig, DiscoveryConfig, GossipSubConfig, P2pConfig, PubSubProtocol,
    TransportProtocol, ValuePayload, ValueSyncConfig,
};
use malachitebft_signing::Signer;
use crypto_suite::{SuitePolicy, SuitePublicKey, SuiteSigningKey};
use malachitebft_signing_ed25519::PrivateKey;
use protocol_types::CryptoSuiteId;
use rand::RngCore;
use protocol_types::Input;
use rand::rngs::StdRng;
use rand::SeedableRng;
use replica::SyncMode;
use tokio::sync::{mpsc, Barrier};
use tokio::task::JoinHandle;

use super::app::{self, AppOpts, Decision, EngineApp, FinalityRole, HeightSeal};
use super::codec::PlxCodec;
use super::context::{Address, PlxContext, Validator, ValidatorSet};
use super::signing::{PlxSigner, PlxVerifier};
use crate::finality::{Collector, FinalityCertificate};
use crate::pq_tunnel::{forward_port, spawn_forwarder, spawn_tunnel_listener, tunnel_addr};
use crate::finality_net::{cert_addr, spawn_cert_server, CertStore};
use crate::intent_gossip::{intent_addr, spawn_listener_with, GossipSecurity, IntentPublisher};
use crate::node::FullViewNode;

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub moniker: String,
    pub consensus: ConsensusConfig,
    pub value_sync: ValueSyncConfig,
}

impl NodeConfig for EngineConfig {
    fn moniker(&self) -> &str {
        &self.moniker
    }

    fn consensus(&self) -> &ConsensusConfig {
        &self.consensus
    }

    fn consensus_mut(&mut self) -> &mut ConsensusConfig {
        &mut self.consensus
    }

    fn value_sync(&self) -> &ValueSyncConfig {
        &self.value_sync
    }

    fn value_sync_mut(&mut self) -> &mut ValueSyncConfig {
        &mut self.value_sync
    }
}

pub struct RunningNode {
    pub address: Address,
    pub app: JoinHandle<()>,
    pub engine: EngineHandle,
    pub decisions: mpsc::UnboundedReceiver<Decision>,
    pub seals: mpsc::UnboundedReceiver<HeightSeal>,
    /// Finality certificates this node assembled as a collector (tiered).
    pub finality: mpsc::UnboundedReceiver<FinalityCertificate>,
    submit: mpsc::UnboundedSender<app::Submitted>,
    intent_listen: Option<JoinHandle<()>>,
    cert_server: Option<JoinHandle<()>>,
    tunnels: Vec<JoinHandle<()>>,
}

impl RunningNode {
    pub fn offer(&self, input: Input) -> Result<()> {
        self.submit
            .send((input, None))
            .map_err(|_| eyre::eyre!("intent submit closed"))
    }

    /// Offer an owner-signed intent (ADR 0033).
    pub fn offer_signed(&self, input: Input, auth: crate::order_auth::OrderAuth) -> Result<()> {
        self.submit
            .send((input, Some(auth)))
            .map_err(|_| eyre::eyre!("intent submit closed"))
    }

    /// Offer a batch of owner-signed intents back to back.
    pub fn offer_all_signed(
        &self,
        batch: impl IntoIterator<Item = (Input, crate::order_auth::OrderAuth)>,
    ) -> Result<()> {
        for (input, auth) in batch {
            self.submit
                .send((input, Some(auth)))
                .map_err(|_| eyre::eyre!("intent submit closed"))?;
        }
        Ok(())
    }

    pub fn offer_all(&self, inputs: impl IntoIterator<Item = Input>) -> Result<()> {
        for input in inputs {
            self.offer(input)?;
        }
        Ok(())
    }

    pub async fn shutdown(self) -> Result<()> {
        let _ = self.engine.actor.kill_and_wait(None).await;
        self.app.abort();
        self.engine.handle.abort();
        if let Some(listen) = self.intent_listen {
            listen.abort();
        }
        if let Some(server) = self.cert_server {
            server.abort();
        }
        for t in self.tunnels {
            t.abort();
        }
        Ok(())
    }
}

pub struct ValidatorKeys {
    pub private: SuiteSigningKey,
    pub validator: Validator,
}

/// Localhost EngineBuilder cluster. Broadcast pubsub matches M4a (GossipSub
/// default mesh D=6 is a bad fit at n=4; keep the same protocol when scaling
/// so M4b is the same test). Transport is the M4c variable. `app` is the
/// M4 isolate matrix (GossipSub / stub Validate / skip WAL).
#[derive(Clone, Debug)]
pub struct ClusterSpec {
    pub n: usize,
    pub base_port: usize,
    pub transport: TransportProtocol,
    pub protocol: PubSubProtocol,
    pub ready_delay: Duration,
    /// Empty-wait for a first offer (ADR 0019 / 0020). Not Malachite peer-wait.
    pub gossip_spread: Duration,
    /// Unused for admit after ADR 0021 (kept so old knobs do not break benches).
    pub gossip_quiet: Duration,
    pub app: AppOpts,
    pub sync: SyncMode,
    /// Applied to every replica before the first `GetValue` (loaded-book heights).
    pub preload: Vec<Input>,
    /// Localhost TCP fan-out of pending intents before each height seal (ADR 0017 / 0018).
    pub intent_gossip: bool,
    /// Validator key suite (ADR 0030). Default classical Ed25519.
    pub suite: CryptoSuiteId,
    /// Weakest suite every node accepts on votes / proposals.
    pub min_suite: CryptoSuiteId,
    /// Per-node key suites, overriding `suite` (downgrade experiments).
    pub key_suites: Option<Vec<CryptoSuiteId>>,
    /// Handshake + AEAD on intent gossip under `min_suite` (ADR 0030).
    pub secure_gossip: bool,
    /// Tiered finality with this many collectors (ADR 0031): votes sign with
    /// the classical part of each key; finality signatures use the full key.
    pub tiered: Option<usize>,
    /// Re-send finality signatures to the next collectors after this long
    /// without a `Certified` notice.
    pub finality_failover: Duration,
    /// Validators whose cert server refuses to serve (withholding test knob).
    pub withhold_certs: Vec<usize>,
    /// Account intents must be owner-signed under this policy (ADR 0033).
    pub signed_orders: Option<SuitePolicy>,
    /// Malachite's TCP connections run inside the suite handshake + AEAD
    /// tunnel (ADR 0034). TCP only.
    pub pq_tunnel: bool,
}

impl ClusterSpec {
    pub fn tcp(n: usize, base_port: usize) -> Self {
        Self {
            n,
            base_port,
            transport: TransportProtocol::Tcp,
            protocol: PubSubProtocol::Broadcast,
            ready_delay: ready_delay_for(n),
            gossip_spread: gossip_spread_default(),
            gossip_quiet: gossip_quiet_default(),
            app: AppOpts::default(),
            sync: SyncMode::Height,
            preload: Vec::new(),
            intent_gossip: false,
            suite: CryptoSuiteId::ClassicalV0,
            min_suite: CryptoSuiteId::ClassicalV0,
            key_suites: None,
            secure_gossip: false,
            tiered: None,
            finality_failover: Duration::from_secs(1),
            withhold_certs: Vec::new(),
            signed_orders: None,
            pq_tunnel: false,
        }
    }

    /// Hybrid validator keys and a hybrid-only policy (ADR 0030).
    pub fn hybrid(mut self) -> Self {
        self.suite = CryptoSuiteId::HybridV1;
        self.min_suite = CryptoSuiteId::HybridV1;
        self
    }

    /// Tiered finality (ADR 0031): hybrid keys; consensus votes carry only the
    /// Ed25519 part; after decide each validator sends one hybrid finality
    /// signature to `collectors` validators over hybrid-secured gossip.
    pub fn tiered(mut self, collectors: usize) -> Self {
        self.suite = CryptoSuiteId::HybridV1;
        self.min_suite = CryptoSuiteId::HybridV1;
        self.tiered = Some(collectors);
        self.with_secure_gossip()
    }

    /// Tunnel Malachite's connections through the suite handshake (ADR 0034).
    pub fn with_pq_tunnel(mut self) -> Self {
        self.pq_tunnel = true;
        self
    }

    /// Require owner signatures on account intents (ADR 0033).
    pub fn with_signed_orders(mut self, policy: SuitePolicy) -> Self {
        self.signed_orders = Some(policy);
        self
    }

    pub fn with_key_suites(mut self, suites: Vec<CryptoSuiteId>) -> Self {
        self.key_suites = Some(suites);
        self
    }

    pub fn with_min_suite(mut self, min: CryptoSuiteId) -> Self {
        self.min_suite = min;
        self
    }

    pub fn quic(n: usize, base_port: usize) -> Self {
        let mut spec = Self::tcp(n, base_port);
        spec.transport = TransportProtocol::Quic;
        spec
    }

    /// GossipSub mesh with flood-publish **off** (otherwise it is broadcast).
    pub fn gossipsub_mesh(mut self) -> Self {
        self.protocol = mesh_gossipsub();
        self
    }

    pub fn with_app(mut self, app: AppOpts) -> Self {
        self.app = app;
        self
    }

    pub fn relaxed_wal(mut self) -> Self {
        self.sync = SyncMode::Relaxed;
        self
    }

    pub fn with_preload(mut self, preload: Vec<Input>) -> Self {
        self.preload = preload;
        self
    }

    pub fn with_intent_gossip(mut self) -> Self {
        self.intent_gossip = true;
        self
    }

    /// Intent gossip over the suite handshake and sealed frames (ADR 0030).
    pub fn with_secure_gossip(mut self) -> Self {
        self.intent_gossip = true;
        self.secure_gossip = true;
        self
    }

    pub fn with_gossip_spread(mut self, spread: Duration) -> Self {
        self.gossip_spread = spread;
        self
    }

    pub fn with_gossip_quiet(mut self, quiet: Duration) -> Self {
        self.gossip_quiet = quiet;
        self
    }

    pub fn transport_name(&self) -> &'static str {
        match self.transport {
            TransportProtocol::Tcp => "tcp",
            TransportProtocol::Quic => "quic",
        }
    }

    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            PubSubProtocol::Broadcast => "broadcast",
            PubSubProtocol::GossipSub(_) => "gossipsub",
        }
    }
}

/// D=6 mesh, no peer scoring, no explicit peering, no flood publish.
pub fn mesh_gossipsub() -> PubSubProtocol {
    PubSubProtocol::GossipSub(GossipSubConfig::new(6, 12, 4, 2, false, false, false))
}

pub fn ready_delay_for(n: usize) -> Duration {
    Duration::from_millis(1500 + 80 * n as u64)
}

/// Localhost wait for a first offer (ADR 0019 / 0020). Not WAN.
pub fn gossip_spread_default() -> Duration {
    Duration::from_millis(100)
}

/// Historical 0020 quiet. Admit is ACK of `id(set)` (ADR 0021).
pub fn gossip_quiet_default() -> Duration {
    Duration::from_millis(20)
}

pub fn make_validators(n: usize, seed: u64) -> Vec<ValidatorKeys> {
    make_validators_with(&vec![CryptoSuiteId::ClassicalV0; n], seed)
}

/// One validator per entry of `suites`, keys deterministic from `seed`.
pub fn make_validators_with(suites: &[CryptoSuiteId], seed: u64) -> Vec<ValidatorKeys> {
    let mut rng = StdRng::seed_from_u64(seed);
    suites
        .iter()
        .map(|&suite| {
            let mut secret = [0u8; 32];
            rng.fill_bytes(&mut secret);
            let private = SuiteSigningKey::from_seed(suite, secret);
            let validator = Validator::new(private.public(), 1);
            ValidatorKeys { private, validator }
        })
        .collect()
}

fn replica_key(index: usize) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&(index as u64).to_le_bytes());
    key[8] = 1;
    key
}

fn node_config(index: usize, spec: &ClusterSpec) -> EngineConfig {
    let n = spec.n;
    let listen = spec
        .transport
        .multiaddr("127.0.0.1", spec.base_port + index);
    // With the PQ tunnel, Malachite dials local forwarders only.
    let peers = (0..n)
        .filter(|j| *j != index)
        .map(|j| {
            let port = if spec.pq_tunnel {
                forward_port(spec.base_port, n, index, j)
            } else {
                spec.base_port + j
            };
            spec.transport.multiaddr("127.0.0.1", port)
        })
        .collect();
    let per_ip = (n * 8).max(64);
    EngineConfig {
        moniker: format!("plx-{index}"),
        consensus: ConsensusConfig {
            enabled: true,
            p2p: P2pConfig {
                listen_addr: listen,
                persistent_peers: peers,
                discovery: DiscoveryConfig {
                    enabled: false,
                    max_connections_per_ip: per_ip,
                    num_outbound_peers: n.max(4),
                    num_inbound_peers: n.max(4),
                    ..DiscoveryConfig::default()
                },
                protocol: spec.protocol,
                persistent_peers_only: false,
                ..P2pConfig::default()
            },
            value_payload: ValuePayload::ProposalAndParts,
            wal_replay_delay: Duration::ZERO,
            queue_per_height_capacity: (n * 8).max(500),
            ..ConsensusConfig::default()
        },
        value_sync: ValueSyncConfig {
            enabled: true,
            status_update_interval: Duration::from_secs(1),
            request_timeout: Duration::from_secs(5),
            ..ValueSyncConfig::default()
        },
    }
}

pub async fn start_validator(
    home: impl AsRef<Path>,
    genesis: Genesis,
    keys: &ValidatorKeys,
    validator_set: ValidatorSet,
    inputs: Option<Vec<Input>>,
    index: usize,
    spec: &ClusterSpec,
    ready: Arc<Barrier>,
    roster: Arc<Vec<SuitePublicKey>>,
) -> Result<RunningNode> {
    let home = home.as_ref();
    std::fs::create_dir_all(home)?;
    let wal = home.join("consensus.wal");
    let mut node = FullViewNode::open_with(
        home.join("replica.wal"),
        replica_key(index),
        genesis,
        spec.sync,
    )?;
    if !spec.preload.is_empty() {
        node.preload(&spec.preload)
            .map_err(|e| eyre::eyre!("preload: {e}"))?;
    }
    let config = node_config(index, spec);
    let mut tunnels = Vec::new();
    if spec.pq_tunnel {
        eyre::ensure!(
            matches!(spec.transport, TransportProtocol::Tcp),
            "the PQ tunnel wraps TCP only"
        );
        let sec = GossipSecurity {
            key: keys.private.clone(),
            policy: SuitePolicy { min: spec.min_suite },
            peers: roster.clone(),
        };
        let local = std::net::SocketAddr::from(([127, 0, 0, 1], (spec.base_port + index) as u16));
        tunnels.push(spawn_tunnel_listener(tunnel_addr(spec.base_port, spec.n, index), local, sec.clone()));
        for j in (0..spec.n).filter(|j| *j != index) {
            let bind = std::net::SocketAddr::from((
                [127, 0, 0, 1],
                forward_port(spec.base_port, spec.n, index, j) as u16,
            ));
            tunnels.push(spawn_forwarder(bind, tunnel_addr(spec.base_port, spec.n, j), sec.clone()));
        }
    }
    let address = keys.validator.address;
    // Durable / channel floor: gossip handshake and finality signatures.
    let policy = SuitePolicy { min: spec.min_suite };
    // Tiered: consensus sees only the classical part of each key.
    let (cons_key, cons_policy) = if spec.tiered.is_some() {
        (keys.private.classical(), SuitePolicy::CLASSICAL)
    } else {
        (keys.private.clone(), policy)
    };
    let signer = PlxSigner::new(cons_key.clone(), cons_policy);
    let verifier = PlxVerifier::new(cons_policy);

    let mut rng = StdRng::seed_from_u64(0xC0FFEE + index as u64);
    let net_pk = PrivateKey::generate(&mut rng);
    let keypair = Keypair::ed25519_from_bytes(net_pk.inner().to_bytes().to_vec())
        .map_err(|e| eyre::eyre!("network keypair: {e}"))?;
    // Malachite v0.8 caps validator-proof messages at 1 KiB (network
    // `validator_proof/codec.rs`). A hybrid proof (1 990 B key + 3 379 B
    // signature) does not fit, so hybrid validators join without one: votes
    // and proposals still carry and verify their own hybrid signatures; only
    // the transport-level "this peer is that validator" label is skipped
    // (ADR 0030).
    let identity = if cons_key.suite().has_pq_components() {
        NetworkIdentity::new(config.moniker.clone(), keypair, Some(address.to_string()))
    } else {
        let peer_id_bytes = keypair.public().to_peer_id().to_bytes();
        let proof = signer
            .sign_validator_proof(cons_key.public().encode(), peer_id_bytes)
            .await
            .map_err(|e| eyre::eyre!("validator proof: {e:?}"))?;
        let proof_bytes = PlxCodec
            .encode(&proof)
            .map_err(|e| eyre::eyre!("encode proof: {e}"))?;
        NetworkIdentity::new_validator(
            config.moniker.clone(),
            keypair,
            address.to_string(),
            proof_bytes,
        )
    };

    let (mut channels, engine) = EngineBuilder::new(PlxContext, config)
        .with_default_wal(WalContext::new(wal, PlxCodec))
        .with_default_network(NetworkContext::new(identity, PlxCodec))
        .with_default_sync(SyncContext::new(PlxCodec))
        .with_default_consensus(ConsensusContext::new_validator(
            address,
            Box::new(verifier),
            Box::new(signer),
        ))
        .with_default_request(RequestContext::new(100))
        .build()
        .await?;

    let (tx, rx) = mpsc::unbounded_channel();
    let (seal_tx, seal_rx) = mpsc::unbounded_channel();
    let (submit_tx, submit_rx) = mpsc::unbounded_channel();
    let (inbox, publisher, intent_listen) = if spec.intent_gossip {
        let (gtx, grx) = mpsc::unbounded_channel();
        let bind = intent_addr(spec.base_port, spec.n, index);
        let security = spec.secure_gossip.then(|| GossipSecurity {
            key: keys.private.clone(),
            policy,
            peers: roster.clone(),
        });
        let listen = spawn_listener_with(bind, gtx, security.clone(), spec.signed_orders);
        let peers = (0..spec.n)
            .filter(|j| *j != index)
            .map(|j| intent_addr(spec.base_port, spec.n, j))
            .collect();
        (Some(grx), Some(IntentPublisher::with_security(peers, security)), Some(listen))
    } else {
        (None, None, None)
    };
    let (cert_tx, cert_rx) = mpsc::unbounded_channel();
    let mut state = EngineApp::new(
        node,
        address,
        validator_set,
        inputs,
        tx,
        seal_tx,
        ready,
        spec.ready_delay,
        spec.gossip_spread,
        spec.app,
        inbox,
        submit_rx,
        publisher,
    );
    if let Some(policy) = spec.signed_orders {
        state = state.with_signed_orders(policy);
    }
    let mut cert_server = None;
    if let Some(fanout) = spec.tiered {
        let store = CertStore::default();
        let (rtx, rrx) = mpsc::unbounded_channel();
        cert_server = Some(spawn_cert_server(
            cert_addr(spec.base_port, spec.n, index),
            store.clone(),
            rtx,
            !spec.withhold_certs.contains(&index),
        ));
        state = state.with_finality(FinalityRole {
            key: keys.private.clone(),
            index,
            n: spec.n,
            fanout,
            collector: Collector::new(policy, roster.clone()),
            certs: cert_tx,
            store,
            failover_after: spec.finality_failover,
            recollect: rrx,
            signed: Default::default(),
            certified: Default::default(),
            to_announce: Vec::new(),
        });
    }
    let app = tokio::spawn(async move {
        if let Err(e) = app::run(&mut state, &mut channels).await {
            tracing::error!("app loop ended: {e}");
        }
    });

    Ok(RunningNode {
        address,
        app,
        engine,
        decisions: rx,
        seals: seal_rx,
        finality: cert_rx,
        submit: submit_tx,
        intent_listen,
        cert_server,
        tunnels,
    })
}

/// Four full-view EngineBuilder nodes on localhost TCP (M4a).
pub async fn start_four(
    dir: impl AsRef<Path>,
    genesis: Genesis,
    inputs: [Option<Vec<Input>>; 4],
    base_port: usize,
) -> Result<Vec<RunningNode>> {
    let spec = ClusterSpec::tcp(4, base_port);
    start_cluster(dir, genesis, inputs.to_vec(), spec).await
}

pub async fn start_cluster(
    dir: impl AsRef<Path>,
    genesis: Genesis,
    inputs: Vec<Option<Vec<Input>>>,
    spec: ClusterSpec,
) -> Result<Vec<RunningNode>> {
    let n = spec.n;
    eyre::ensure!(n >= 1, "need at least one validator");
    eyre::ensure!(inputs.len() == n, "inputs len {} != n {n}", inputs.len());
    let dir = dir.as_ref();
    let suites = spec.key_suites.clone().unwrap_or_else(|| vec![spec.suite; n]);
    eyre::ensure!(suites.len() == n, "key_suites len {} != n {n}", suites.len());
    let mut keys = make_validators_with(&suites, 42);
    // Full keys in index order: gossip peers and the finality roster.
    let roster = Arc::new(keys.iter().map(|k| k.private.public()).collect::<Vec<_>>());
    if spec.tiered.is_some() {
        for k in &mut keys {
            k.validator = Validator::new(k.private.public().classical(), 1);
        }
    }
    let set = ValidatorSet::new(keys.iter().map(|k| k.validator.clone()));
    let ready = Arc::new(Barrier::new(n));
    let mut nodes = Vec::with_capacity(n);
    for i in 0..n {
        let home = dir.join(format!("n{i}"));
        nodes.push(
            start_validator(
                home,
                genesis.clone(),
                &keys[i],
                set.clone(),
                inputs[i].clone(),
                i,
                &spec,
                ready.clone(),
                roster.clone(),
            )
            .await?,
        );
    }
    Ok(nodes)
}

pub async fn await_seal(
    node: &mut RunningNode,
    height: u64,
    timeout: Duration,
) -> Result<HeightSeal> {
    loop {
        let s = tokio::time::timeout(timeout, node.seals.recv())
            .await
            .map_err(|_| eyre::eyre!("timeout waiting for seal {height}"))?
            .ok_or_else(|| eyre::eyre!("seal channel closed at height {height}"))?;
        if s.height == height {
            return Ok(s);
        }
        eyre::ensure!(
            s.height < height,
            "expected seal {height}, got {}",
            s.height
        );
    }
}

pub async fn await_decisions(
    nodes: &mut [RunningNode],
    height: u64,
    timeout: Duration,
) -> Result<Vec<Decision>> {
    let mut out = Vec::with_capacity(nodes.len());
    for (i, n) in nodes.iter_mut().enumerate() {
        let d = tokio::time::timeout(timeout, n.decisions.recv())
            .await
            .map_err(|_| eyre::eyre!("timeout waiting for height {height} on node {i}"))?
            .ok_or_else(|| eyre::eyre!("decision channel closed at height {height} on node {i}"))?;
        eyre::ensure!(
            d.height == height,
            "node {i}: expected height {height}, got {}",
            d.height
        );
        out.push(d);
    }
    Ok(out)
}

/// Nearest-rank percentile of millisecond samples. Empty → 0.
pub fn percentile_ms(samples: &[u64], p: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut v = samples.to_vec();
    v.sort_unstable();
    let idx = ((p / 100.0) * (v.len() - 1) as f64).round() as usize;
    v[idx.min(v.len() - 1)]
}

#[derive(Clone, Debug)]
pub struct HeightSample {
    pub height: u64,
    pub id_hex: String,
    pub node_ms: Vec<u64>,
    pub cluster_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ScaleRun {
    pub n: usize,
    pub transport: String,
    pub label: String,
    pub heights: Vec<HeightSample>,
}

impl ScaleRun {
    pub fn node_ms(&self) -> Vec<u64> {
        self.heights
            .iter()
            .flat_map(|h| h.node_ms.iter().copied())
            .collect()
    }

    pub fn cluster_ms(&self) -> Vec<u64> {
        self.heights.iter().map(|h| h.cluster_ms).collect()
    }
}

pub async fn run_heights(
    nodes: &mut [RunningNode],
    heights: u64,
    timeout: Duration,
) -> Result<Vec<HeightSample>> {
    let mut out = Vec::with_capacity(heights as usize);
    for h in 1..=heights {
        let decided = await_decisions(nodes, h, timeout).await?;
        let id = decided[0].id;
        for d in &decided[1..] {
            eyre::ensure!(d.id == id, "split decision at height {h}");
        }
        let node_ms: Vec<u64> = decided
            .iter()
            .map(|d| d.latency.as_millis() as u64)
            .collect();
        let cluster_ms = node_ms.iter().copied().max().unwrap_or(0);
        out.push(HeightSample {
            height: h,
            id_hex: id.to_string(),
            node_ms,
            cluster_ms,
        });
    }
    Ok(out)
}
