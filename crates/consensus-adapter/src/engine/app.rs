//! `AppMsg` loop: GetValue/Validate/Decided call the M4a port (`F` on scratch, WAL on decide).

use std::collections::BTreeMap;
use std::future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use commitments::{value_id, Digest};
use eyre::eyre;
use malachitebft_app_channel::app::engine::host::{HeightParams, Next, SyncedValueOutcome};
use malachitebft_app_channel::app::types::core::{
    ExtendedCommitCertificate, LinearTimeouts, Round, Validity as EngValidity,
};
use malachitebft_app_channel::app::types::sync::RawDecidedValue;
use malachitebft_app_channel::app::types::{LocallyProposedValue, ProposedValue};
use malachitebft_app_channel::{AppMsg, Channels, NetworkMsg};
use malachitebft_engine::util::streaming::{StreamContent, StreamId, StreamMessage};
use protocol_types::{Bytes32, CanonicalDecode, CanonicalEncode, ConsensusValue, Height, Input};
use tokio::sync::{mpsc, Barrier};
use tracing::{error, info};

use super::context::{Address, ConsHeight, PlxContext, PlxValue, ProposalPart, ValidatorSet};
use crate::finality::{collectors_round, max_rounds, Collector, FinalityCertificate, FinalitySig};
use crate::finality_net::CertStore;
use crate::intent_gossip::{GossipFrame, IntentPublisher, SetAck};
use crate::intent_log::intent_id;
use crate::order_auth::{check_order, is_system_input, OrderAuth};
use crate::intent_log::IntentLog;
use crate::node::FullViewNode;
use crate::port::Validity;

#[derive(Clone, Debug)]
pub struct Decision {
    pub height: u64,
    pub id: Digest,
    pub value: ConsensusValue,
    /// StartedRound (first round of this height) → Decided. Excludes the
    /// ConsensusReady peer-wait. Not matching latency (Q-CRY-2).
    pub latency: Duration,
    /// When this replica notified Decided. Compare across nodes for first/last.
    pub decided_at: Instant,
    /// This replica’s Decided(h-1) → Finalized(h-1). Zero at height 1.
    pub decide_to_finalized: Duration,
    /// Finalized(h-1) → admit return (ACK quorum or empty). Zero at height 1.
    pub finalized_to_ack: Duration,
    /// Admit return → StartedRound(h). Zero at height 1.
    pub ack_to_started: Duration,
    /// How `Finalized(h-1)` admitted. `None` at height 1.
    pub admit: Option<AdmitTrace>,
    /// This height's sealed `I`, when [`AppOpts::emit_inputs`] is set (for a
    /// FULL_VIEW follower that builds `π` jobs). `None` otherwise.
    pub inputs: Option<Vec<protocol_types::Input>>,
}

/// First-wave 10k is still arriving after an empty height-1 BFT. Wait this
/// long for completed-wave ACKs before re-fanning a large pending set.
const IN_FLIGHT_GRACE: Duration = Duration::from_millis(180);
/// Below this, recover the tail immediately (later heights, 20–71 kB).
const IN_FLIGHT_PENDING_MIN: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmitPath {
    /// `id(set)` already matched on every voter at `Finalized`.
    Ready,
    /// At least one peer already matched; 50 ms wait completed quorum.
    Grace,
    /// Large pending still in flight; waited without re-fan and quorum landed.
    InFlight,
    /// Re-fan pending, then wait.
    Recover,
    /// Waited for quorum without a re-fan (empty local set).
    Late,
}

#[derive(Clone, Copy, Debug)]
pub struct AdmitTrace {
    pub path: AdmitPath,
    /// Matching ACKs after the first `SetAck` at `Finalized` (includes self).
    pub acks_at_entry: u8,
    pub pending: u32,
    pub fanout_bytes: u64,
}

/// First `StartedRound` of a height, after that height’s `I` is sealed.
#[derive(Clone, Debug)]
pub struct HeightSeal {
    pub height: u64,
}

/// Isolation knobs for the M4b follow-up. Default is M4a/M4b (`F` in Validate, WAL on decide).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AppOpts {
    /// Prevote without replaying `F` / walking the state root.
    pub stub_validate: bool,
    /// Attach the sealed `I` to each [`Decision`] (end-to-end `π` pipeline).
    /// Off by default: cloning a 10k tape per height would skew latency benches.
    pub emit_inputs: bool,
    /// `GetValue` emits a zero-root bundle (no `F`). Implies `stub_validate`.
    pub stub_propose: bool,
    /// `Decided` does not replica-WAL/`F`. Consensus still finalizes `id(v)`.
    pub skip_apply: bool,
}

/// Tiered finality (ADR 0031): after decide, sign `(height, id)` with the full
/// key and send it to `fanout` collectors; collect what arrives here.
pub struct FinalityRole {
    pub key: crypto_suite::SuiteSigningKey,
    pub index: usize,
    pub n: usize,
    pub fanout: usize,
    pub collector: Collector,
    pub certs: mpsc::UnboundedSender<FinalityCertificate>,
    /// Certificates this node serves (`finality_net`).
    pub store: CertStore,
    /// Re-send to the next collectors when no `Certified` notice arrives in
    /// this long (crashed or silent collector).
    pub failover_after: Duration,
    /// `RECOLLECT` requests from consumers (withholding collector).
    pub recollect: mpsc::UnboundedReceiver<(u64, u32)>,
    /// This node's own finality signatures: (signature, round, last sent).
    pub signed: BTreeMap<u64, (FinalitySig, u32, Instant)>,
    /// Heights some collector announced.
    pub certified: std::collections::BTreeSet<u64>,
    /// Certificates formed here, to announce.
    pub to_announce: Vec<u64>,
}

/// Own signatures kept for recollect.
const FINALITY_KEEP: u64 = 4096;
/// A `RECOLLECT` for a height sent this recently, at the same or an earlier
/// round, is ignored (repeat requests cannot make this node re-send in a loop).
const RECOLLECT_GAP: Duration = Duration::from_millis(100);

pub struct EngineApp {
    node: FullViewNode,
    address: Address,
    validators: ValidatorSet,
    log: IntentLog,
    inbox: Option<mpsc::UnboundedReceiver<GossipFrame>>,
    submit: mpsc::UnboundedReceiver<Submitted>,
    publisher: Option<IntentPublisher>,
    acks: BTreeMap<Address, (Digest, u32)>,
    current_height: ConsHeight,
    proposed: BTreeMap<(u64, i64), PlxValue>,
    seen: BTreeMap<Digest, (PlxValue, Address, Round)>,
    decided: BTreeMap<u64, (PlxValue, ExtendedCommitCertificate<PlxContext>)>,
    parts: BTreeMap<Digest, Vec<StreamMessage<ProposalPart>>>,
    notify: mpsc::UnboundedSender<Decision>,
    seals: mpsc::UnboundedSender<HeightSeal>,
    ready: Arc<Barrier>,
    ready_delay: Duration,
    gossip_spread: Duration,
    height_started: Option<(u64, Instant)>,
    last_decided: Option<Instant>,
    last_finalized: Option<Instant>,
    last_admit: Option<Instant>,
    last_ack_pub: Option<(Digest, Instant)>,
    /// Height whose set this node last ACKed (ADR 0027 tag rule).
    acked_height: Option<u64>,
    last_admit_trace: Option<AdmitTrace>,
    opts: AppOpts,
    finality: Option<FinalityRole>,
    /// Signed orders (ADR 0033): policy, and owner signatures by intent id
    /// so re-fans carry them.
    orders: Option<crypto_suite::SuitePolicy>,
    auths: std::collections::HashMap<Digest, OrderAuth>,
}

/// A client intent and, when orders are signed, its owner's signature.
pub type Submitted = (Input, Option<OrderAuth>);

impl EngineApp {
    pub fn with_signed_orders(mut self, policy: crypto_suite::SuitePolicy) -> Self {
        self.orders = Some(policy);
        self
    }

    pub fn with_finality(mut self, role: FinalityRole) -> Self {
        self.finality = Some(role);
        self
    }

    /// Sign the decided value with the full key and send it to round 0.
    async fn finality_sign(&mut self, height: u64, id: Digest) {
        let Some(role) = self.finality.as_mut() else {
            return;
        };
        let fs = FinalitySig::sign(&role.key, role.index as u16, height, id);
        role.signed.insert(height, (fs, 0, Instant::now()));
        if let Some(&oldest) = role.signed.keys().next() {
            if height > oldest + FINALITY_KEEP {
                role.signed.remove(&oldest);
            }
        }
        self.finality_send(height, 0).await;
    }

    /// Send this node's signature for `height` to the round-`round` collectors.
    async fn finality_send(&mut self, height: u64, round: u32) {
        let Some(role) = self.finality.as_mut() else {
            return;
        };
        let Some((fs, r, sent)) = role.signed.get_mut(&height) else {
            return;
        };
        *r = (*r).max(round);
        *sent = Instant::now();
        let fs = fs.clone();
        let targets = collectors_round(height, role.n, role.fanout, round);
        if targets.contains(&role.index) {
            Self::collect(role, fs.clone());
        }
        // Publisher slots skip this node's own index.
        let me = role.index;
        let slots: Vec<usize> = targets
            .iter()
            .filter(|&&j| j != me)
            .map(|&j| if j < me { j } else { j - 1 })
            .collect();
        if let Some(publisher) = self.publisher.as_mut() {
            let len = publisher.publish_finality(&slots, &fs).await;
            super::codec::wire::finality(len as usize * slots.len());
        }
        self.finality_announce().await;
    }

    /// A consumer's `RECOLLECT` (`finality_net`): re-send unless this height
    /// was just sent at this round or a later one.
    async fn finality_recollect(&mut self, height: u64, round: u32) {
        let Some(role) = self.finality.as_ref() else {
            return;
        };
        if round >= max_rounds(role.n, role.fanout) {
            return;
        }
        match role.signed.get(&height) {
            Some((_, r, sent)) if round > *r || sent.elapsed() >= RECOLLECT_GAP => {
                self.finality_send(height, round).await
            }
            _ => {}
        }
    }

    fn collect(role: &mut FinalityRole, fs: FinalitySig) {
        match role.collector.add(fs) {
            Ok(Some(cert)) => {
                let h = cert.height;
                role.store.lock().unwrap().insert(h, cert.clone());
                role.certified.insert(h);
                role.to_announce.push(h);
                let _ = role.certs.send(cert);
            }
            Ok(None) => {}
            Err(e) => tracing::warn!("finality signature rejected: {e}"),
        }
    }

    async fn finality_announce(&mut self) {
        let Some(role) = self.finality.as_mut() else {
            return;
        };
        let heights = std::mem::take(&mut role.to_announce);
        if let Some(publisher) = self.publisher.as_mut() {
            for h in heights {
                publisher.publish_certified(h).await;
            }
        }
    }

    /// Failover: heights with no `Certified` notice after `failover_after`
    /// go to the next round's collectors.
    async fn finality_tick(&mut self) {
        let Some(role) = self.finality.as_ref() else {
            return;
        };
        let rounds = max_rounds(role.n, role.fanout);
        let due: Vec<(u64, u32)> = role
            .signed
            .iter()
            .filter(|(h, (_, r, sent))| {
                !role.certified.contains(h) && r + 1 < rounds && sent.elapsed() >= role.failover_after
            })
            .map(|(h, (_, r, _))| (*h, r + 1))
            .collect();
        for (h, r) in due {
            tracing::info!(height = h, round = r, "finality failover");
            self.finality_send(h, r).await;
        }
    }

    pub fn new(
        node: FullViewNode,
        address: Address,
        validators: ValidatorSet,
        inputs: Option<Vec<Input>>,
        notify: mpsc::UnboundedSender<Decision>,
        seals: mpsc::UnboundedSender<HeightSeal>,
        ready: Arc<Barrier>,
        ready_delay: Duration,
        gossip_spread: Duration,
        opts: AppOpts,
        inbox: Option<mpsc::UnboundedReceiver<GossipFrame>>,
        submit: mpsc::UnboundedReceiver<Submitted>,
        publisher: Option<IntentPublisher>,
    ) -> Self {
        Self {
            node,
            address,
            validators,
            log: IntentLog::from_batch(inputs),
            inbox,
            submit,
            publisher,
            acks: BTreeMap::new(),
            current_height: ConsHeight::new(1),
            proposed: BTreeMap::new(),
            seen: BTreeMap::new(),
            decided: BTreeMap::new(),
            parts: BTreeMap::new(),
            notify,
            seals,
            ready,
            ready_delay,
            gossip_spread,
            height_started: None,
            last_decided: None,
            last_finalized: None,
            last_admit: None,
            last_ack_pub: None,
            acked_height: None,
            last_admit_trace: None,
            opts,
            finality: None,
            orders: None,
            auths: Default::default(),
        }
    }

    /// `None` = missing `I` (prevote nil). Seals the replicated set (ADR 0016).
    /// First seal of a height consumes pending; later offers wait for the next height.
    fn inputs_for(&mut self, height: u64) -> Option<&[Input]> {
        self.log.tape(height)
    }

    fn ingest_now(&mut self) {
        let mut frames = Vec::new();
        if let Some(rx) = self.inbox.as_mut() {
            while let Ok(frame) = rx.try_recv() {
                frames.push(frame);
            }
        }
        for frame in frames {
            self.take_frame(frame);
        }
    }

    fn take_frame(&mut self, frame: GossipFrame) {
        match frame {
            GossipFrame::Intent { height, input, auth } => {
                // Clients and peers may not inject protocol inputs (any mode).
                if is_system_input(&input) {
                    tracing::warn!("system input from gossip dropped");
                    return;
                }
                // The listener already verified `auth` (ADR 0033). Keep it only
                // while the intent is pending, so a replayed, already-decided
                // intent cannot grow the table (decide prunes the rest).
                let id = intent_id(&input);
                if self.log.offer_at(input, height) {
                    if let Some(a) = auth {
                        self.auths.insert(id, a);
                    }
                }
            }
            GossipFrame::SetAck(ack) => self.record_ack(ack),
            GossipFrame::Finality(fs) => {
                if let Some(role) = self.finality.as_mut() {
                    Self::collect(role, fs);
                }
            }
            GossipFrame::Certified { height } => {
                if let Some(role) = self.finality.as_mut() {
                    role.certified.insert(height);
                }
            }
        }
    }

    fn record_ack(&mut self, ack: SetAck) {
        let voter = Address::new(ack.voter);
        if !self
            .validators
            .validators
            .iter()
            .any(|v| v.address == voter)
        {
            return;
        }
        self.acks.insert(voter, (ack.set_id, ack.count));
    }

    fn matching_acks(&self) -> usize {
        let id = self.log.pending_set_id();
        self.acks.values().filter(|(got, _)| *got == id).count()
    }

    fn set_quorum(&self) -> bool {
        self.matching_acks() >= self.validators.validators.len()
    }

    fn peer_acked_local(&self) -> bool {
        if self.log.pending_len() == 0 {
            return false;
        }
        let id = self.log.pending_set_id();
        self.acks
            .iter()
            .any(|(voter, (got, _))| *voter != self.address && *got == id)
    }

    /// ACK only a completed wave: local `id(set)` already published by a peer
    /// (the offerer’s post-batch ACK), not every growing ingest.
    async fn ack_if_wave_complete(&mut self) {
        if self.peer_acked_local() {
            self.publish_set_ack().await;
        }
    }

    /// Target height for intents this node accepts from clients (ADR 0027):
    /// the next unsealed height, unless this node already ACKed that height's
    /// set (peers may then seal it without these), in which case the one after.
    fn offer_height(&self) -> u64 {
        let h = self.log.next_open();
        if self.acked_height == Some(h) {
            h + 1
        } else {
            h
        }
    }

    async fn publish_set_ack(&mut self) {
        // Even if this exact id was published before (e.g. an empty set for an
        // earlier height), peers may count it for this height: from here on,
        // new client intents target the next one.
        self.acked_height = Some(self.log.next_open());
        let set_id = self.log.pending_set_id();
        self.acks
            .insert(self.address, (set_id, self.log.pending_len() as u32));
        if self.last_ack_pub.map(|(id, _)| id) == Some(set_id) {
            return;
        }
        self.last_ack_pub = Some((set_id, Instant::now()));
        let ack = SetAck {
            voter: *self.address.as_bytes(),
            set_id,
            count: self.log.pending_len() as u32,
        };
        if let Some(publisher) = self.publisher.as_mut() {
            publisher.publish_ack(ack).await;
        }
    }

    async fn wait_set_quorum(&mut self, deadline: Instant) -> bool {
        loop {
            if self.set_quorum() {
                return true;
            }
            let rest = deadline.saturating_duration_since(Instant::now());
            if rest.is_zero() {
                return self.set_quorum();
            }
            self.ingest_until(Instant::now() + rest.min(Duration::from_millis(2)))
                .await;
            self.ack_if_wave_complete().await;
        }
    }

    async fn drain_submit(&mut self) {
        let mut batch = Vec::new();
        while let Ok(input) = self.submit.try_recv() {
            batch.push(input);
        }
        if !batch.is_empty() {
            self.accept_batch(batch).await;
        }
    }

    async fn accept_queued(&mut self, first: Submitted) {
        let mut batch = vec![first];
        while let Ok(input) = self.submit.try_recv() {
            batch.push(input);
        }
        self.accept_batch(batch).await;
    }

    async fn fanout_pending(&mut self) -> u64 {
        let pending = self.log.pending();
        let auths = &self.auths;
        if let Some(publisher) = self.publisher.as_mut() {
            publisher.publish_signed(&pending, |i| auths.get(&intent_id(i))).await
        } else {
            0
        }
    }

    async fn accept_batch(&mut self, inputs: Vec<Submitted>) {
        if !self.log.has_view() {
            return;
        }
        let inputs: Vec<Submitted> = inputs.into_iter().filter(|(i, _)| !is_system_input(i)).collect();
        let inputs = match self.orders {
            Some(policy) => verify_all(policy, inputs).await,
            None => inputs,
        };
        let h = self.offer_height();
        let mut tagged: Vec<(u64, Input)> = Vec::with_capacity(inputs.len());
        for (input, auth) in inputs {
            // Only newly pending intents keep a signature and are published.
            if !self.log.offer_at(input.clone(), h) {
                continue;
            }
            if let Some(a) = auth {
                self.auths.insert(intent_id(&input), a);
            }
            tagged.push((h, input));
        }
        // Same connection as the ACK below, so peers see the intents first.
        let auths = &self.auths;
        if let Some(publisher) = self.publisher.as_mut() {
            publisher.publish_signed(&tagged, |i| auths.get(&intent_id(i))).await;
        }
        self.publish_set_ack().await;
    }

    async fn gossip_window(&mut self, wait: Duration) {
        if let Some(publisher) = self.publisher.as_mut() {
            publisher.connect_all().await;
        }
        let _ = self.fanout_pending().await;
        if wait.is_zero() {
            self.ingest_now();
            self.drain_submit().await;
        } else {
            self.ingest_until(Instant::now() + wait).await;
        }
    }

    /// Wait for a first offer, then until every voter ACKs `id(set)` (ADR 0021).
    /// Do not re-fan the set first: it was published at offer. A large pending
    /// set waits for in-flight ACKs before recover ([m4-inter-split]).
    async fn admit_window(&mut self) {
        if let Some(publisher) = self.publisher.as_mut() {
            publisher.connect_all().await;
        }
        self.ingest_now();
        self.drain_submit().await;
        let empty_deadline = Instant::now() + self.gossip_spread;
        while self.log.pending_len() == 0 && Instant::now() < empty_deadline {
            let rest = empty_deadline.saturating_duration_since(Instant::now());
            if rest.is_zero() {
                break;
            }
            self.ingest_until(Instant::now() + rest.min(Duration::from_millis(5)))
                .await;
        }
        self.publish_set_ack().await;
        let acks_at_entry = self.matching_acks() as u8;
        let pending = self.log.pending_len() as u32;
        if self.set_quorum() {
            self.last_admit_trace = Some(AdmitTrace {
                path: AdmitPath::Ready,
                acks_at_entry,
                pending,
                fanout_bytes: 0,
            });
            return;
        }
        if self.log.pending_len() >= IN_FLIGHT_PENDING_MIN
            && self
                .wait_set_quorum(Instant::now() + IN_FLIGHT_GRACE)
                .await
        {
            self.last_admit_trace = Some(AdmitTrace {
                path: AdmitPath::InFlight,
                acks_at_entry,
                pending,
                fanout_bytes: 0,
            });
            return;
        }
        if self.peer_acked_local()
            && self
                .wait_set_quorum(Instant::now() + Duration::from_millis(50))
                .await
        {
            self.last_admit_trace = Some(AdmitTrace {
                path: AdmitPath::Grace,
                acks_at_entry,
                pending,
                fanout_bytes: 0,
            });
            return;
        }
        let mut fanout_bytes = 0;
        let path = if self.log.pending_len() > 0 {
            fanout_bytes = self.fanout_pending().await;
            self.publish_set_ack().await;
            AdmitPath::Recover
        } else {
            AdmitPath::Late
        };
        let _ = self
            .wait_set_quorum(Instant::now() + Duration::from_secs(5))
            .await;
        self.last_admit_trace = Some(AdmitTrace {
            path,
            acks_at_entry,
            pending,
            fanout_bytes,
        });
    }

    async fn ingest_until(&mut self, deadline: Instant) {
        loop {
            let rest = deadline.saturating_duration_since(Instant::now());
            if rest.is_zero() {
                self.ingest_now();
                self.drain_submit().await;
                self.ack_if_wave_complete().await;
                return;
            }
            tokio::select! {
                _ = tokio::time::sleep(rest) => {
                    self.ingest_now();
                    self.drain_submit().await;
                    self.ack_if_wave_complete().await;
                    return;
                }
                msg = inbox_recv(&mut self.inbox) => {
                    match msg {
                        Some(frame) => {
                            self.take_frame(frame);
                            self.ack_if_wave_complete().await;
                        }
                        None => {
                            self.inbox = None;
                        }
                    }
                }
                msg = self.submit.recv() => {
                    if let Some(input) = msg {
                        self.accept_queued(input).await;
                    }
                }
            }
        }
    }

    fn notify_seal(&self, height: u64) {
        let _ = self.seals.send(HeightSeal { height });
    }

    fn notify_decision(&mut self, height: u64, id: Digest, value: ConsensusValue) {
        let now = Instant::now();
        let (latency, ack_to_started) = match self.height_started {
            Some((h, t)) if h == height => {
                let to_start = self
                    .last_admit
                    .map(|ack| t.saturating_duration_since(ack))
                    .unwrap_or(Duration::ZERO);
                (now.saturating_duration_since(t), to_start)
            }
            _ => (Duration::ZERO, Duration::ZERO),
        };
        let (decide_to_finalized, finalized_to_ack) =
            match (self.last_decided, self.last_finalized, self.last_admit) {
                (Some(prev), Some(fin), Some(ack)) if height > 1 => (
                    fin.saturating_duration_since(prev),
                    ack.saturating_duration_since(fin),
                ),
                _ => (Duration::ZERO, Duration::ZERO),
            };
        if !self.auths.is_empty() {
            if let Some(tape) = self.log.tape(height) {
                for i in tape {
                    self.auths.remove(&intent_id(i));
                }
            }
        }
        let inputs = if self.opts.emit_inputs {
            self.log.tape(height).map(|t| t.to_vec())
        } else {
            None
        };
        let _ = self.notify.send(Decision {
            height,
            id,
            value,
            inputs,
            latency,
            decided_at: now,
            decide_to_finalized,
            finalized_to_ack,
            ack_to_started,
            admit: self.last_admit_trace,
        });
        self.last_decided = Some(now);
    }

    fn height_params(&self) -> HeightParams<PlxContext> {
        let timeouts = LinearTimeouts {
            propose: Duration::from_millis(800),
            propose_delta: Duration::from_millis(200),
            prevote: Duration::from_millis(400),
            prevote_delta: Duration::from_millis(200),
            precommit: Duration::from_millis(400),
            precommit_delta: Duration::from_millis(200),
            rebroadcast: Duration::from_millis(1600),
            max_timeout: Duration::from_secs(10),
        };
        HeightParams::new(
            self.validators.clone(),
            timeouts,
            Some(Duration::from_millis(50)),
        )
    }

    fn stream_id(height: ConsHeight, round: Round, addr: &Address) -> StreamId {
        let mut id = Vec::with_capacity(36);
        id.extend_from_slice(&height.as_u64().to_le_bytes());
        id.extend_from_slice(&round.as_i64().to_le_bytes());
        id.extend_from_slice(addr.as_bytes());
        StreamId::new(Bytes::from(id))
    }

    fn stream_parts(
        &self,
        height: ConsHeight,
        round: Round,
        value: PlxValue,
    ) -> Vec<StreamMessage<ProposalPart>> {
        let stream_id = Self::stream_id(height, round, &self.address);
        vec![
            StreamMessage::new(
                stream_id.clone(),
                0,
                StreamContent::Data(ProposalPart {
                    height,
                    round,
                    proposer: self.address,
                    value,
                }),
            ),
            StreamMessage::new(stream_id, 1, StreamContent::Fin),
        ]
    }

    fn dummy_value(&self, height: u64) -> PlxValue {
        let parent = if height <= 1 {
            ConsensusValue::GENESIS_PARENT
        } else {
            self.decided
                .get(&(height - 1))
                .map(|(v, _)| value_id(&v.0).to_bytes32())
                .unwrap_or(ConsensusValue::GENESIS_PARENT)
        };
        PlxValue(ConsensusValue {
            parent,
            height: Height(height),
            state_root: Bytes32::ZERO,
            input_commitment: Bytes32::ZERO,
            settlement_commitment: Bytes32::ZERO,
        })
    }

    fn engine_validity(&mut self, value: &ConsensusValue) -> EngValidity {
        if self.opts.stub_validate || self.opts.stub_propose {
            return match self.inputs_for(value.height.0) {
                None => EngValidity::Invalid,
                Some(_) => EngValidity::Valid,
            };
        }
        let inputs = self.inputs_for(value.height.0).map(|i| i.to_vec());
        match self.node.validate_proposal(value, inputs.as_deref()) {
            Validity::Valid => EngValidity::Valid,
            Validity::Invalid | Validity::InsufficientView => EngValidity::Invalid,
        }
    }

    fn apply_if_valid(&mut self, value: &PlxValue) {
        if self.opts.skip_apply {
            return;
        }
        let Some(inputs) = self.inputs_for(value.0.height.0).map(|i| i.to_vec()) else {
            return;
        };
        let _ = self.node.decide(&value.0, &inputs);
    }
}

pub async fn run(state: &mut EngineApp, channels: &mut Channels<PlxContext>) -> eyre::Result<()> {
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            msg = channels.consensus.recv() => {
                let Some(msg) = msg else {
                    return Err(eyre!("consensus channel closed"));
                };
                handle_app_msg(state, channels, msg).await?;
            }
            frame = inbox_recv(&mut state.inbox) => {
                match frame {
                    Some(frame) => {
                        state.take_frame(frame);
                        state.finality_announce().await;
                        state.ack_if_wave_complete().await;
                    }
                    None => state.inbox = None,
                }
            }
            input = state.submit.recv() => {
                if let Some(input) = input {
                    state.accept_queued(input).await;
                }
            }
            req = recollect_recv(&mut state.finality) => {
                if let Some((h, r)) = req {
                    state.finality_recollect(h, r).await;
                }
            }
            _ = tick.tick(), if state.finality.is_some() => {
                state.finality_tick().await;
            }
        }
    }
}

/// Check owner signatures on all cores, off the app thread; keeps the valid
/// intents in order (ADR 0033).
async fn verify_all(policy: crypto_suite::SuitePolicy, inputs: Vec<Submitted>) -> Vec<Submitted> {
    tokio::task::spawn_blocking(move || {
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        let chunk = inputs.len().div_ceil(threads).max(1);
        let ok: Vec<bool> = std::thread::scope(|sc| {
            let parts: Vec<_> = inputs
                .chunks(chunk)
                .map(|c| sc.spawn(move || c.iter().map(|(i, a)| check_order(policy, i, a.as_ref()).is_ok()).collect::<Vec<_>>()))
                .collect();
            parts.into_iter().flat_map(|p| p.join().expect("verify thread")).collect()
        });
        let dropped = ok.iter().filter(|o| !**o).count();
        if dropped > 0 {
            tracing::debug!(dropped, "client intents rejected (signature)");
        }
        inputs.into_iter().zip(ok).filter_map(|(x, ok)| ok.then_some(x)).collect()
    })
    .await
    .expect("verify task")
}

async fn recollect_recv(role: &mut Option<FinalityRole>) -> Option<(u64, u32)> {
    match role.as_mut() {
        Some(r) => r.recollect.recv().await,
        None => future::pending().await,
    }
}

async fn inbox_recv(
    inbox: &mut Option<mpsc::UnboundedReceiver<GossipFrame>>,
) -> Option<GossipFrame> {
    match inbox.as_mut() {
        Some(rx) => rx.recv().await,
        None => future::pending().await,
    }
}

async fn handle_app_msg(
    state: &mut EngineApp,
    channels: &mut Channels<PlxContext>,
    msg: AppMsg<PlxContext>,
) -> eyre::Result<()> {
    match msg {
        AppMsg::ConsensusReady { reply } => {
            state.ready.wait().await;
            let wait = if state.ready_delay.is_zero() {
                state.gossip_spread
            } else {
                state.ready_delay
            };
            state.gossip_window(wait).await;
            let start = ConsHeight::new(1);
            info!(%start, "consensus ready");
            let params = state.height_params();
            let _ = reply.send((start, params));
        }
        AppMsg::StartedRound {
            height,
            round,
            proposer: _,
            role: _,
            reply_value,
        } => {
            state.ingest_now();
            state.drain_submit().await;
            state.current_height = height;
            let first = match state.height_started {
                Some((h, _)) if h == height.as_u64() => false,
                _ => {
                    state.height_started = Some((height.as_u64(), Instant::now()));
                    true
                }
            };
            if first {
                // Seal before notify so a client offer is the next height.
                // Skip under stub knobs: isolate floor must not pay 4-way
                // tape-sort of 10k when F is off (that was the 0.18→0.25 move).
                if !state.opts.stub_validate && !state.opts.stub_propose {
                    let n = state.inputs_for(height.as_u64()).map_or(0, |t| t.len());
                    tracing::debug!(
                        height = height.as_u64(),
                        sealed = n,
                        late = state.log.late(),
                        "sealed I"
                    );
                }
                state.notify_seal(height.as_u64());
            }
            let pending_src: Vec<_> = state
                .seen
                .values()
                .filter(|(v, _, r)| v.0.height.0 == height.as_u64() && *r == round)
                .map(|(v, proposer, r)| (*v, *proposer, *r))
                .collect();
            let pending: Vec<_> = pending_src
                .into_iter()
                .map(|(v, proposer, r)| ProposedValue {
                    height,
                    round: r,
                    valid_round: Round::Nil,
                    proposer,
                    value: v,
                    validity: state.engine_validity(&v.0),
                })
                .collect();
            // Shared-`I` bound: scratch-apply local tape while the proposer
            // runs GetValue. Validate is then an `id(v)` check. Skip under
            // stub knobs so isolate cells stay meaningful. No-op if a
            // scratch for this height already exists (reproposal / seen).
            if !state.opts.stub_validate && !state.opts.stub_propose {
                if let Some(inputs) = state.inputs_for(height.as_u64()).map(|i| i.to_vec()) {
                    state.node.speculate(&inputs);
                }
            }
            let _ = reply_value.send(pending);
        }
        AppMsg::GetValue {
            height,
            round,
            timeout: _,
            reply,
        } => {
            let inputs = state.inputs_for(height.as_u64()).unwrap_or(&[]).to_vec();
            let value = match state.proposed.get(&(height.as_u64(), round.as_i64())) {
                Some(v) => *v,
                None => {
                    let v = if state.opts.stub_propose {
                        state.dummy_value(height.as_u64())
                    } else {
                        PlxValue(state.node.get_value(&inputs))
                    };
                    state.proposed.insert((height.as_u64(), round.as_i64()), v);
                    v
                }
            };
            let local = LocallyProposedValue::new(height, round, value);
            let _ = reply.send(local);
            let parts = state.stream_parts(height, round, value);
            state
                .seen
                .insert(value.id().0, (value, state.address, round));
            state.parts.insert(value.id().0, parts.clone());
            for part in parts {
                channels
                    .network
                    .send(NetworkMsg::PublishProposalPart(part))
                    .await
                    .map_err(|e| eyre::eyre!("publish part: {e}"))?;
            }
        }
        AppMsg::ReceivedProposalPart {
            from: _,
            part,
            reply,
        } => {
            let proposed = match &part.content {
                StreamContent::Data(p) => {
                    let value = p.value;
                    let height = p.height;
                    let round = p.round;
                    let proposer = p.proposer;
                    let id = value.id().0;
                    state.seen.entry(id).or_insert((value, proposer, round));
                    let validity = state.engine_validity(&value.0);
                    Some(ProposedValue {
                        height,
                        round,
                        valid_round: Round::Nil,
                        proposer,
                        value,
                        validity,
                    })
                }
                StreamContent::Fin => None,
            };
            let _ = reply.send(proposed);
        }
        AppMsg::Decided {
            certificate,
            extensions,
            reply,
        } => {
            info!(
                height = %certificate.height,
                value = %certificate.value_id,
                "decided"
            );
            let id = certificate.value_id.0;
            if let Some((value, _, _)) = state.seen.get(&id).cloned() {
                state.apply_if_valid(&value);
                let ext = ExtendedCommitCertificate::from_commit_certificate_and_extensions(
                    certificate,
                    extensions,
                );
                let height = ext.height.as_u64();
                state.decided.insert(height, (value, ext));
                state.notify_decision(height, id, value.0);
                state.finality_sign(height, id).await;
            } else if let Some(v) = state
                .proposed
                .values()
                .find(|v| value_id(&v.0) == id)
                .copied()
            {
                state.apply_if_valid(&v);
                let ext = ExtendedCommitCertificate::from_commit_certificate_and_extensions(
                    certificate,
                    extensions,
                );
                let height = ext.height.as_u64();
                state.decided.insert(height, (v, ext));
                state.notify_decision(height, id, v.0);
                state.finality_sign(height, id).await;
            }
            let _ = reply.send(());
        }
        AppMsg::Finalized {
            certificate,
            extensions: _,
            evidence: _,
            reply,
        } => {
            let next = certificate.height.increment();
            state.current_height = next;
            state.last_finalized = Some(Instant::now());
            if state.publisher.is_some() {
                state.admit_window().await;
            }
            state.last_admit = Some(Instant::now());
            let params = state.height_params();
            let _ = reply.send(Next::Start(next, params));
        }
        AppMsg::ProcessSyncedValue {
            height,
            round,
            proposer,
            value_bytes,
            reply,
        } => {
            let outcome = match ConsensusValue::decode_slice(&value_bytes) {
                Ok(value) => {
                    let pv = PlxValue(value);
                    let validity = state.engine_validity(&pv.0);
                    state.seen.insert(pv.id().0, (pv, proposer, round));
                    SyncedValueOutcome::Verdict(ProposedValue {
                        height,
                        round,
                        valid_round: Round::Nil,
                        proposer,
                        value: pv,
                        validity,
                    })
                }
                Err(_) => SyncedValueOutcome::PeerFault,
            };
            let _ = reply.send(outcome);
        }
        AppMsg::GetDecidedValues { range, reply } => {
            let mut values = Vec::new();
            let mut h = *range.start();
            while h.as_u64() <= range.end().as_u64() {
                if let Some((value, cert)) = state.decided.get(&h.as_u64()) {
                    values.push(RawDecidedValue {
                        certificate: cert.clone(),
                        value_bytes: Bytes::from(value.0.encode_vec()),
                    });
                }
                h = h.increment();
                if h.as_u64() == 0 {
                    break;
                }
            }
            let _ = reply.send(values);
        }
        AppMsg::GetHistoryMinHeight { reply } => {
            let min = state
                .decided
                .keys()
                .next()
                .copied()
                .map(ConsHeight::new)
                .unwrap_or(ConsHeight::new(1));
            let _ = reply.send(min);
        }
        AppMsg::RestreamProposal {
            height,
            round: _,
            valid_round: _,
            address: _,
            value_id,
        } => {
            if let Some(parts) = state.parts.get(&value_id.0).cloned() {
                for part in parts {
                    channels
                        .network
                        .send(NetworkMsg::PublishProposalPart(part))
                        .await?;
                }
            } else {
                error!(%height, "no cached parts to restream");
            }
        }
        AppMsg::ExtendVote { reply, .. } => {
            let _ = reply.send(None);
        }
        AppMsg::VerifyVoteExtension { reply, .. } => {
            let _ = reply.send(Ok(()));
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn encode_value(value: &ConsensusValue) -> Bytes {
    Bytes::from(value.encode_vec())
}

#[allow(dead_code)]
fn decode_value(bytes: &[u8]) -> Option<ConsensusValue> {
    ConsensusValue::decode_slice(bytes).ok()
}
