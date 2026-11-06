//! Deterministic treap (cartesian tree) hashed with BLAKE3.
//!
//! Priority is `BLAKE3("plx/treap/prio/v1" || key)`, so the tree shape — and
//! therefore the root — depends only on the key/value set, not insertion order.
//! Insert / update rehash one BST path (rotations restore the heap). Delete
//! still merges subtrees. Expected hashes are O(log n), not three hashed splits.
//!
//! This is a **set commitment**, not a validity proof, and not yet the CLOB
//! consensus root (Q-CRY-2 experiment).

use std::cell::{Cell, RefCell};
use std::sync::OnceLock;

use protocol_types::{CanonicalEncode, EncodeBuf, ENCODING_VERSION};

use crate::treap_witness::{TreapOp, TreapStep, WitnessNode};
use crate::Digest;

pub const TREAP_PRIO_DOMAIN: &[u8] = b"plx/treap/prio/v1";
pub const TREAP_NODE_DOMAIN: &[u8] = b"plx/treap/node/v1";
pub const TREAP_EMPTY_DOMAIN: &[u8] = b"plx/treap/empty/v1";

thread_local! {
    static PRIO_CALLS: Cell<u64> = const { Cell::new(0) };
    static NODE_CALLS: Cell<u64> = const { Cell::new(0) };
    static EMPTY_COMPUTE: Cell<u64> = const { Cell::new(0) };
    static EMPTY_LOOKUP: Cell<u64> = const { Cell::new(0) };
    static NODE_TRACE: RefCell<Option<Vec<NodeDigestOpening>>> = const { RefCell::new(None) };
    static PRIO_TRACE: RefCell<Option<Vec<Vec<u8>>>> = const { RefCell::new(None) };
    /// Chronological `C'` preimages (prio + `node_digest`) in apply order.
    static C_PRIME_TRACE: RefCell<Option<Vec<Vec<u8>>>> = const { RefCell::new(None) };
    /// True while any of the three traces above is active. Lets the hash path
    /// skip building openings / preimages when nobody is recording.
    static TRACING: Cell<bool> = const { Cell::new(false) };
}

fn refresh_tracing() {
    let on = NODE_TRACE.with(|t| t.borrow().is_some())
        || PRIO_TRACE.with(|t| t.borrow().is_some())
        || C_PRIME_TRACE.with(|t| t.borrow().is_some());
    TRACING.with(|c| c.set(on));
}

fn tracing() -> bool {
    TRACING.with(Cell::get)
}

/// `C'` hash mode. Production is [`TreapHash::Sha256`] (ADR 0024).
/// [`TreapHash::Blake3`] is `C'` v1 (ADR 0013), kept for the Plonky3 BLAKE3
/// circuits and their fixtures. The other modes are isolate-only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TreapHash {
    /// `C'` v1: BLAKE3 (ADR 0013).
    Blake3,
    /// Same tree walk and allocations. `rehash` is a zero digest. Priority is
    /// production SHA-256 so the shape matches production.
    NopRehash,
    /// `C'` v1 hashes plus a call counter (isolate only).
    Blake3Count,
    /// Production `C'` (ADR 0024): the same preimages and domains, hashed with
    /// SHA-256 (hardware SHA natively; accelerated in zkVM guests).
    #[default]
    Sha256,
}

/// [`TreapHash::Blake3Count`] breakdown. `blake3` is real hasher work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TreapHashCalls {
    pub prio: u64,
    pub node: u64,
    /// Times the empty-domain digest was actually hashed (once per process after cache).
    pub empty_compute: u64,
    /// Missing-child lookups (would have hashed empty before the cache).
    pub empty_lookup: u64,
}

impl TreapHashCalls {
    pub fn blake3(self) -> u64 {
        self.prio + self.node + self.empty_compute
    }
}

/// Take and reset the [`TreapHash::Blake3Count`] counters.
pub fn take_treap_hash_calls() -> TreapHashCalls {
    TreapHashCalls {
        prio: PRIO_CALLS.with(|c| c.replace(0)),
        node: NODE_CALLS.with(|c| c.replace(0)),
        empty_compute: EMPTY_COMPUTE.with(|c| c.replace(0)),
        empty_lookup: EMPTY_LOOKUP.with(|c| c.replace(0)),
    }
}

fn counting(mode: TreapHash) -> bool {
    mode == TreapHash::Blake3Count
}

fn empty_digest() -> Digest {
    static EMPTY: OnceLock<Digest> = OnceLock::new();
    *EMPTY.get_or_init(|| {
        EMPTY_COMPUTE.with(|c| c.set(c.get() + 1));
        Digest::from_bytes(&[], TREAP_EMPTY_DOMAIN)
    })
}

/// `C'` v1 (BLAKE3) empty-child digest. Production uses
/// [`treap_empty_digest_with`] with the map's mode.
pub fn treap_empty_digest() -> Digest {
    empty_digest()
}

static SHA256_IMPL: OnceLock<fn(&[u8]) -> [u8; 32]> = OnceLock::new();

/// Install the SHA-256 used for production `C'` (for example a zkVM guest's
/// accelerator, whose one-call API is ~3× cheaper than driving it through the
/// `sha2` crate). It **must** compute standard SHA-256. The first call wins;
/// returns false if one was already set. The default is the `sha2` crate.
pub fn set_sha256_impl(f: fn(&[u8]) -> [u8; 32]) -> bool {
    SHA256_IMPL.set(f).is_ok()
}

/// SHA-256 of the concatenation, hashed in **one** call. Feeding parts
/// through repeated `update`s goes through the crate's block buffer, which in
/// a zkVM guest cost ~4× the accelerated compression itself (216 B node:
/// ~2.8K vs ~0.7K cycles). Preimages here are ≤ 256 B, so a stack buffer fits.
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    // Word-aligned, so accelerators that read u32 words need no extra copy.
    #[repr(align(4))]
    struct Aligned([u8; 256]);
    let len: usize = parts.iter().map(|p| p.len()).sum();
    let mut stack = Aligned([0u8; 256]);
    let mut heap = Vec::new();
    let buf: &mut [u8] = if len <= stack.0.len() {
        &mut stack.0[..len]
    } else {
        heap.resize(len, 0);
        &mut heap
    };
    let mut at = 0;
    for p in parts {
        buf[at..at + p.len()].copy_from_slice(p);
        at += p.len();
    }
    sha256_once(buf)
}

/// SHA-256 of one contiguous buffer, via [`set_sha256_impl`] if installed.
pub(crate) fn sha256_once(buf: &[u8]) -> [u8; 32] {
    if let Some(f) = SHA256_IMPL.get() {
        return f(buf);
    }
    use sha2::Digest as _;
    sha2::Sha256::digest(buf).into()
}

/// Empty-child digest under `mode` (the map root when empty). The SHA-256
/// form hashes the same bytes as [`Digest::from_bytes`] of the empty domain.
pub fn treap_empty_digest_with(mode: TreapHash) -> Digest {
    if mode != TreapHash::Sha256 {
        return empty_digest();
    }
    static EMPTY: OnceLock<Digest> = OnceLock::new();
    *EMPTY.get_or_init(|| {
        Digest(sha256(&[TREAP_EMPTY_DOMAIN, &ENCODING_VERSION.to_le_bytes(), &0u64.to_le_bytes()]))
    })
}

/// `node_digest` under `mode`, with no trace or counter side effects.
pub fn treap_node_hash_with(
    mode: TreapHash,
    left: &Digest,
    key: &[u8],
    value: &[u8],
    right: &Digest,
) -> Digest {
    let parts: [&[u8]; 8] = [
        TREAP_NODE_DOMAIN,
        &ENCODING_VERSION.to_le_bytes(),
        &left.0,
        &(key.len() as u64).to_le_bytes(),
        key,
        &(value.len() as u64).to_le_bytes(),
        value,
        &right.0,
    ];
    if mode == TreapHash::Sha256 {
        return Digest(sha256(&parts));
    }
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p);
    }
    Digest(*h.finalize().as_bytes())
}

/// Treap heap key under `mode`: LE u64 of `H(TREAP_PRIO_DOMAIN ‖ key)`.
/// [`TreapHash::NopRehash`] uses the production (SHA-256) priority.
pub fn priority_u64_with(mode: TreapHash, key: &[u8]) -> u64 {
    if matches!(mode, TreapHash::Sha256 | TreapHash::NopRehash) {
        let out = sha256(&[TREAP_PRIO_DOMAIN, key]);
        return u64::from_le_bytes(out[..8].try_into().expect("sha256 is 32 bytes"));
    }
    priority_u64(key)
}

/// One `node_digest` call. Isolate / prove witness, not the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeDigestOpening {
    pub left: Digest,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub right: Digest,
    pub out: Digest,
}

impl NodeDigestOpening {
    pub fn preimage(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(99 + self.key.len() + self.value.len());
        m.extend_from_slice(TREAP_NODE_DOMAIN);
        m.extend_from_slice(&ENCODING_VERSION.to_le_bytes());
        m.extend_from_slice(&self.left.0);
        m.extend_from_slice(&(self.key.len() as u64).to_le_bytes());
        m.extend_from_slice(&self.key);
        m.extend_from_slice(&(self.value.len() as u64).to_le_bytes());
        m.extend_from_slice(&self.value);
        m.extend_from_slice(&self.right.0);
        m
    }
}

/// Record subsequent [`node_digest`] calls until [`take_node_digest_trace`].
pub fn start_node_digest_trace() {
    NODE_TRACE.with(|t| *t.borrow_mut() = Some(Vec::new()));
    refresh_tracing();
}

/// Take and stop the [`start_node_digest_trace`] buffer.
pub fn take_node_digest_trace() -> Vec<NodeDigestOpening> {
    let out = NODE_TRACE.with(|t| t.borrow_mut().take().unwrap_or_default());
    refresh_tracing();
    out
}

/// `TREAP_PRIO_DOMAIN || key`. OrderId → 33 B; OwnerId → 49 B. One BLAKE3 block.
pub fn prio_preimage(key: &[u8]) -> Vec<u8> {
    let mut pre = Vec::with_capacity(TREAP_PRIO_DOMAIN.len() + key.len());
    pre.extend_from_slice(TREAP_PRIO_DOMAIN);
    pre.extend_from_slice(key);
    pre
}

/// Record subsequent [`priority`] preimages until [`take_prio_trace`].
pub fn start_prio_trace() {
    PRIO_TRACE.with(|t| *t.borrow_mut() = Some(Vec::new()));
    refresh_tracing();
}

/// Take and stop the [`start_prio_trace`] buffer.
pub fn take_prio_trace() -> Vec<Vec<u8>> {
    let out = PRIO_TRACE.with(|t| t.borrow_mut().take().unwrap_or_default());
    refresh_tracing();
    out
}

/// Record subsequent prio + [`node_digest`] preimages in call order until
/// [`take_c_prime_trace`]. Independent of the split node/prio traces.
pub fn start_c_prime_trace() {
    C_PRIME_TRACE.with(|t| *t.borrow_mut() = Some(Vec::new()));
    refresh_tracing();
}

/// Take and stop the [`start_c_prime_trace`] buffer (chronological `C'` hashes).
pub fn take_c_prime_trace() -> Vec<Vec<u8>> {
    let out = C_PRIME_TRACE.with(|t| t.borrow_mut().take().unwrap_or_default());
    refresh_tracing();
    out
}

fn push_c_prime(pre: Vec<u8>) {
    C_PRIME_TRACE.with(|t| {
        if let Some(buf) = t.borrow_mut().as_mut() {
            buf.push(pre);
        }
    });
}

/// BLAKE3 of one treap node (ADR 0013). Not a STARK.
pub fn treap_node_digest(left: Digest, key: &[u8], value: &[u8], right: Digest) -> Digest {
    node_digest(left, key, value, right, TreapHash::Blake3)
}

/// `C'` v1 (BLAKE3) heap key: LE u64 of `BLAKE3(TREAP_PRIO_DOMAIN ‖ key)`.
pub fn priority_u64(key: &[u8]) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(TREAP_PRIO_DOMAIN);
    h.update(key);
    let out = *h.finalize().as_bytes();
    u64::from_le_bytes(out[..8].try_into().expect("blake3 is 32 bytes"))
}

fn priority(key: &[u8], mode: TreapHash) -> u64 {
    if counting(mode) {
        PRIO_CALLS.with(|c| c.set(c.get() + 1));
    }
    if !tracing() {
        return priority_u64_with(mode, key);
    }
    let pre = prio_preimage(key);
    PRIO_TRACE.with(|t| {
        if let Some(buf) = t.borrow_mut().as_mut() {
            buf.push(pre.clone());
        }
    });
    push_c_prime(pre);
    priority_u64_with(mode, key)
}

fn node_digest(left: Digest, key: &[u8], value: &[u8], right: Digest, mode: TreapHash) -> Digest {
    if counting(mode) {
        NODE_CALLS.with(|c| c.set(c.get() + 1));
    }
    if mode == TreapHash::NopRehash {
        return Digest([0; 32]);
    }
    let out = treap_node_hash_with(mode, &left, key, value, &right);
    if !tracing() {
        return out;
    }
    let opening = NodeDigestOpening {
        left,
        key: key.to_vec(),
        value: value.to_vec(),
        right,
        out,
    };
    push_c_prime(opening.preimage());
    NODE_TRACE.with(|t| {
        if let Some(v) = t.borrow_mut().as_mut() {
            v.push(opening);
        }
    });
    out
}

#[derive(Clone, Debug)]
struct Node {
    key: Vec<u8>,
    value: Vec<u8>,
    prio: u64,
    /// Valid only when `!dirty`.
    hash: Digest,
    /// Lazy mode: subtree changed since `hash` was computed.
    dirty: bool,
    left: Link,
    right: Link,
}

type Link = Option<Box<Node>>;

fn child_hash(link: &Link, mode: TreapHash) -> Digest {
    match link {
        Some(n) => n.hash,
        None => {
            if counting(mode) {
                EMPTY_LOOKUP.with(|c| c.set(c.get() + 1));
            }
            if mode == TreapHash::NopRehash {
                Digest([0; 32])
            } else {
                treap_empty_digest_with(mode)
            }
        }
    }
}

/// Production `C'` hashes lazily: a mutation marks its path dirty and each
/// dirty node is hashed once when a root is read, instead of once per
/// mutation. Same digests (a node's hash depends only on the final tree).
/// Tracing and the v1 / isolate modes stay eager: their openings are per step.
fn lazy(mode: TreapHash) -> bool {
    mode == TreapHash::Sha256 && !tracing()
}

fn rehash(n: &mut Node, mode: TreapHash) {
    if lazy(mode) {
        n.dirty = true;
        return;
    }
    for c in [&mut n.left, &mut n.right].into_iter().flatten() {
        flush(c, mode);
    }
    compute(n, mode);
}

fn compute(n: &mut Node, mode: TreapHash) {
    n.hash = node_digest(
        child_hash(&n.left, mode),
        &n.key,
        &n.value,
        child_hash(&n.right, mode),
        mode,
    );
    n.dirty = false;
}

/// Hash every dirty node below and including `n`, children first.
fn flush(n: &mut Node, mode: TreapHash) {
    if !n.dirty {
        return;
    }
    for c in [&mut n.left, &mut n.right].into_iter().flatten() {
        flush(c, mode);
    }
    compute(n, mode);
}

/// `n`'s digest without mutating (recomputes dirty nodes on the fly).
fn hash_of(n: &Node, mode: TreapHash) -> Digest {
    if !n.dirty {
        return n.hash;
    }
    let child = |l: &Link| match l {
        Some(c) => hash_of(c, mode),
        None => treap_empty_digest_with(mode),
    };
    node_digest(child(&n.left), &n.key, &n.value, child(&n.right), mode)
}

fn new_node(key: Vec<u8>, value: Vec<u8>, mode: TreapHash) -> Box<Node> {
    let prio = priority(&key, mode);
    let mut n = Box::new(Node {
        key,
        value,
        prio,
        hash: Digest([0; 32]),
        dirty: true,
        left: None,
        right: None,
    });
    rehash(&mut n, mode);
    n
}

fn heap_before(a: &Node, b: &Node) -> bool {
    a.prio > b.prio || (a.prio == b.prio && a.key < b.key)
}

fn rotate_right(mut n: Box<Node>, mode: TreapHash) -> Box<Node> {
    let mut l = n.left.take().expect("rotate_right");
    n.left = l.right.take();
    rehash(&mut n, mode);
    l.right = Some(n);
    rehash(&mut l, mode);
    l
}

fn rotate_left(mut n: Box<Node>, mode: TreapHash) -> Box<Node> {
    let mut r = n.right.take().expect("rotate_left");
    n.right = r.left.take();
    rehash(&mut n, mode);
    r.left = Some(n);
    rehash(&mut r, mode);
    r
}

/// One BST walk. Rehash on the way back. Rotate to restore the heap.
/// Same cartesian tree as split+merge (priority = hash of key).
fn upsert_rec(t: Link, key: Vec<u8>, value: Vec<u8>, mode: TreapHash) -> (Link, bool) {
    let Some(mut n) = t else {
        return (Some(new_node(key, value, mode)), true);
    };
    match key.as_slice().cmp(n.key.as_slice()) {
        std::cmp::Ordering::Equal => {
            n.value = value;
            rehash(&mut n, mode);
            (Some(n), false)
        }
        std::cmp::Ordering::Less => {
            let (left, inserted) = upsert_rec(n.left.take(), key, value, mode);
            n.left = left;
            if n.left.as_ref().is_some_and(|l| heap_before(l, &n)) {
                n = rotate_right(n, mode);
            } else {
                rehash(&mut n, mode);
            }
            (Some(n), inserted)
        }
        std::cmp::Ordering::Greater => {
            let (right, inserted) = upsert_rec(n.right.take(), key, value, mode);
            n.right = right;
            if n.right.as_ref().is_some_and(|r| heap_before(r, &n)) {
                n = rotate_left(n, mode);
            } else {
                rehash(&mut n, mode);
            }
            (Some(n), inserted)
        }
    }
}

/// All keys in `a` must be < all keys in `b`.
fn merge(a: Link, b: Link, mode: TreapHash) -> Link {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(mut a), Some(mut b)) => {
            if heap_before(&a, &b) {
                a.right = merge(a.right, Some(b), mode);
                rehash(&mut a, mode);
                Some(a)
            } else {
                b.left = merge(Some(a), b.left, mode);
                rehash(&mut b, mode);
                Some(b)
            }
        }
    }
}

fn remove_rec(t: Link, key: &[u8], mode: TreapHash) -> (Link, bool) {
    let Some(mut n) = t else {
        return (None, false);
    };
    match key.cmp(n.key.as_slice()) {
        std::cmp::Ordering::Less => {
            let (left, found) = remove_rec(n.left.take(), key, mode);
            n.left = left;
            rehash(&mut n, mode);
            (Some(n), found)
        }
        std::cmp::Ordering::Greater => {
            let (right, found) = remove_rec(n.right.take(), key, mode);
            n.right = right;
            rehash(&mut n, mode);
            (Some(n), found)
        }
        std::cmp::Ordering::Equal => (merge(n.left.take(), n.right.take(), mode), true),
    }
}

fn find<'a>(t: Option<&'a Node>, key: &[u8]) -> Option<&'a [u8]> {
    let n = t?;
    match key.cmp(n.key.as_slice()) {
        std::cmp::Ordering::Less => find(n.left.as_deref(), key),
        std::cmp::Ordering::Greater => find(n.right.as_deref(), key),
        std::cmp::Ordering::Equal => Some(n.value.as_slice()),
    }
}

/// Ordered map with a BLAKE3 root unique for a given key/value set.
#[derive(Clone, Debug)]
pub struct HashedMap {
    root: Link,
    len: usize,
    hash: TreapHash,
}

impl Default for HashedMap {
    fn default() -> Self {
        Self::new()
    }
}

impl HashedMap {
    pub fn new() -> Self {
        Self::with_hash(TreapHash::default())
    }

    pub fn with_hash(hash: TreapHash) -> Self {
        Self {
            root: None,
            len: 0,
            hash,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn root(&self) -> Digest {
        match &self.root {
            Some(n) => hash_of(n, self.hash),
            None => treap_empty_digest_with(self.hash),
        }
    }

    /// Hash all pending (lazy) changes so later [`Self::root`] reads are free.
    pub fn flush(&mut self) {
        if let Some(n) = self.root.as_mut() {
            flush(n, self.hash);
        }
    }

    pub fn hash_mode(&self) -> TreapHash {
        self.hash
    }

    /// Build from entries in **strictly increasing** key order with one
    /// priority and one `node_digest` per entry (linear-time cartesian-tree
    /// build). Same root as upserting the entries in any order. Panics if the
    /// keys are not strictly increasing.
    pub fn from_sorted(hash: TreapHash, entries: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>) -> Self {
        // `stack` is the right spine; each entry's right child is still open.
        let mut stack: Vec<Box<Node>> = Vec::new();
        let mut len = 0usize;
        for (key, value) in entries {
            if let Some(top) = stack.last() {
                assert!(top.key < key, "from_sorted: keys must be strictly increasing");
            }
            let prio = priority(&key, hash);
            let mut node = Box::new(Node {
                key,
                value,
                prio,
                hash: Digest([0; 32]),
                dirty: true,
                left: None,
                right: None,
            });
            let mut last: Link = None;
            while stack.last().is_some_and(|t| heap_before(&node, t)) {
                let mut t = stack.pop().expect("non-empty");
                t.right = last.take();
                rehash(&mut t, hash);
                last = Some(t);
            }
            node.left = last;
            stack.push(node);
            len += 1;
        }
        let mut last: Link = None;
        while let Some(mut t) = stack.pop() {
            t.right = last.take();
            rehash(&mut t, hash);
            last = Some(t);
        }
        Self { root: last, len, hash }
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        find(self.root.as_deref(), key)
    }

    pub fn upsert(&mut self, key: &[u8], value: &[u8]) {
        let (root, inserted) =
            upsert_rec(self.root.take(), key.to_vec(), value.to_vec(), self.hash);
        self.root = root;
        if inserted {
            self.len += 1;
        }
    }

    pub fn upsert_encoded(&mut self, key: &impl CanonicalEncode, value: &impl CanonicalEncode) {
        self.upsert(&key.encode_vec(), &value.encode_vec());
    }

    pub fn remove(&mut self, key: &[u8]) -> bool {
        let (root, found) = remove_rec(self.root.take(), key, self.hash);
        self.root = root;
        if found {
            self.len -= 1;
        }
        found
    }

    pub fn remove_encoded(&mut self, key: &impl CanonicalEncode) -> bool {
        self.remove(&key.encode_vec())
    }

    /// Path witness for [`Self::upsert`] against the current root. Read-only.
    pub fn upsert_step(&self, key: &[u8], value: &[u8]) -> TreapStep {
        let path = self.search_path(key);
        let found = path.last().is_some_and(|n| n.key == key);
        let insert_at = if found {
            0
        } else {
            let p = priority_u64_with(self.hash, key);
            let new = Node {
                key: key.to_vec(),
                value: Vec::new(),
                prio: p,
                hash: Digest([0; 32]),
                dirty: false,
                left: None,
                right: None,
            };
            path.iter()
                .position(|n| heap_before(&new, n))
                .unwrap_or(path.len())
        };
        TreapStep {
            op: TreapOp::Upsert {
                key: key.to_vec(),
                value: value.to_vec(),
            },
            path: path.iter().map(|n| witness_node(n, self.hash)).collect(),
            insert_at,
            left_spine: Vec::new(),
            right_spine: Vec::new(),
        }
    }

    /// Path witness for [`Self::remove`] against the current root. Read-only.
    pub fn remove_step(&self, key: &[u8]) -> TreapStep {
        let path = self.search_path(key);
        let (mut left_spine, mut right_spine) = (Vec::new(), Vec::new());
        if let Some(n) = path.last().filter(|n| n.key == key) {
            let mut a = n.left.as_deref();
            while let Some(x) = a {
                left_spine.push(witness_node(x, self.hash));
                a = x.right.as_deref();
            }
            let mut b = n.right.as_deref();
            while let Some(x) = b {
                right_spine.push(witness_node(x, self.hash));
                b = x.left.as_deref();
            }
        }
        TreapStep {
            op: TreapOp::Remove { key: key.to_vec() },
            path: path.iter().map(|n| witness_node(n, self.hash)).collect(),
            insert_at: 0,
            left_spine,
            right_spine,
        }
    }

    /// Nodes on the BST search path for `key`, root first.
    fn search_path(&self, key: &[u8]) -> Vec<&Node> {
        let mut path = Vec::new();
        let mut t = self.root.as_deref();
        while let Some(n) = t {
            path.push(n);
            t = match key.cmp(n.key.as_slice()) {
                std::cmp::Ordering::Less => n.left.as_deref(),
                std::cmp::Ordering::Greater => n.right.as_deref(),
                std::cmp::Ordering::Equal => None,
            };
        }
        path
    }
}

fn witness_node(n: &Node, mode: TreapHash) -> WitnessNode {
    let hash = |l: &Link| l.as_ref().map_or_else(|| treap_empty_digest_with(mode), |c| hash_of(c, mode));
    WitnessNode {
        key: n.key.clone(),
        value: n.value.clone(),
        left: hash(&n.left),
        right: hash(&n.right),
    }
}

pub fn encode_bytes(value: &impl CanonicalEncode) -> Vec<u8> {
    let mut buf = EncodeBuf::new();
    value.encode(&mut buf);
    buf.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> Vec<u8> {
        vec![n]
    }

    #[test]
    fn empty_root_is_domain_separated() {
        let m = HashedMap::new();
        assert_ne!(m.root().0, [0u8; 32]);
        assert_eq!(m.root(), treap_empty_digest_with(TreapHash::Sha256));
        let v1 = HashedMap::with_hash(TreapHash::Blake3);
        assert_eq!(v1.root(), empty_digest());
        assert_eq!(v1.root(), treap_empty_digest());
        assert_ne!(m.root(), v1.root());
    }

    #[test]
    fn leaf_upsert_is_node_digest_of_empty_children() {
        let mut m = HashedMap::new();
        m.upsert(b"key", b"value");
        let empty = treap_empty_digest_with(TreapHash::Sha256);
        let want = treap_node_hash_with(TreapHash::Sha256, &empty, b"key", b"value", &empty);
        assert_eq!(m.root(), want);
        let mut v1 = HashedMap::with_hash(TreapHash::Blake3);
        v1.upsert(b"key", b"value");
        let empty = treap_empty_digest();
        assert_eq!(v1.root(), treap_node_digest(empty, b"key", b"value", empty));
    }

    #[test]
    fn node_digest_trace_records_leaf() {
        start_node_digest_trace();
        let mut m = HashedMap::new();
        m.upsert(b"key", b"value");
        let t = take_node_digest_trace();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].out, m.root());
        assert_eq!(t[0].preimage().len(), 99 + 3 + 5);
    }

    #[test]
    fn prio_preimage_is_domain_plus_key() {
        start_prio_trace();
        let mut m = HashedMap::new();
        m.upsert(b"key", b"value");
        let t = take_prio_trace();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0], prio_preimage(b"key"));
        assert_eq!(t[0].len(), TREAP_PRIO_DOMAIN.len() + 3);
        assert_eq!(&t[0][..TREAP_PRIO_DOMAIN.len()], TREAP_PRIO_DOMAIN);
        let mut h = blake3::Hasher::new();
        h.update(&t[0]);
        let out = *h.finalize().as_bytes();
        let want = u64::from_le_bytes(out[..8].try_into().unwrap());
        assert_eq!(priority(b"key", TreapHash::Blake3), want);
    }

    #[test]
    fn insertion_order_does_not_change_root() {
        let mut a = HashedMap::new();
        let mut b = HashedMap::new();
        for k in [1u8, 2, 3, 4, 5] {
            a.upsert(&key(k), &[k]);
        }
        for k in [5u8, 1, 4, 2, 3] {
            b.upsert(&key(k), &[k]);
        }
        assert_eq!(a.root(), b.root());
        assert_eq!(a.len(), 5);
    }

    #[test]
    fn remove_restores_previous_root() {
        let mut m = HashedMap::new();
        m.upsert(&key(1), b"a");
        let r1 = m.root();
        m.upsert(&key(2), b"b");
        assert_ne!(m.root(), r1);
        assert!(m.remove(&key(2)));
        assert_eq!(m.root(), r1);
        assert!(!m.remove(&key(2)));
    }

    #[test]
    fn update_and_remove_non_root_keys() {
        let mut m = HashedMap::new();
        for k in 0u8..30 {
            m.upsert(&key(k), &[k]);
        }
        assert_eq!(m.len(), 30);
        m.upsert(&key(10), b"x");
        assert_eq!(m.len(), 30);
        assert_eq!(m.get(&key(10)), Some(b"x".as_slice()));
        assert!(m.remove(&key(10)));
        assert_eq!(m.len(), 29);
        assert!(m.get(&key(10)).is_none());
        let mut rebuilt = HashedMap::new();
        for k in 0u8..30 {
            if k != 10 {
                rebuilt.upsert(&key(k), &[k]);
            }
        }
        assert_eq!(m.root(), rebuilt.root());
    }

    #[test]
    fn shuffle_same_set() {
        let mut rng = 0xC0FFEE_u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut items: Vec<(u8, u8)> = (0u8..40).map(|i| (i, i.wrapping_mul(3))).collect();
        let mut canonical = HashedMap::new();
        for (k, v) in &items {
            canonical.upsert(&key(*k), &[*v]);
        }
        for _ in 0..20 {
            for i in (1..items.len()).rev() {
                let j = (next() as usize) % (i + 1);
                items.swap(i, j);
            }
            let mut m = HashedMap::new();
            for (k, v) in &items {
                m.upsert(&key(*k), &[*v]);
            }
            assert_eq!(m.root(), canonical.root());
        }
    }

    #[test]
    fn from_sorted_matches_upserts() {
        let mut rng = 0x5EED_u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for mode in [TreapHash::Sha256, TreapHash::Blake3] {
            for n in [0usize, 1, 2, 3, 7, 64, 500, 3000] {
                let mut items: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
                    .map(|i| ((next() % 100_000).to_be_bytes().to_vec(), vec![i as u8; i % 9]))
                    .collect();
                items.sort();
                items.dedup_by(|a, b| a.0 == b.0);
                let mut up = HashedMap::with_hash(mode);
                for (k, v) in items.iter().rev() {
                    up.upsert(k, v);
                }
                let built = HashedMap::from_sorted(mode, items.clone());
                assert_eq!(built.root(), up.root(), "{mode:?} n={n}");
                assert_eq!(built.len(), up.len());
                // The built map keeps working as a treap.
                let mut b2 = built.clone();
                let mut u2 = up.clone();
                for k in 0..50u64 {
                    b2.upsert(&(k * 7919).to_be_bytes(), b"x");
                    u2.upsert(&(k * 7919).to_be_bytes(), b"x");
                }
                assert_eq!(b2.root(), u2.root());
            }
        }
    }

    #[test]
    #[should_panic(expected = "strictly increasing")]
    fn from_sorted_rejects_unsorted() {
        let _ = HashedMap::from_sorted(TreapHash::Sha256, vec![(vec![2], vec![]), (vec![1], vec![])]);
    }

    #[test]
    fn nop_rehash_keeps_len_and_get() {
        let mut m = HashedMap::with_hash(TreapHash::NopRehash);
        for k in 0u8..30 {
            m.upsert(&key(k), &[k]);
        }
        assert_eq!(m.len(), 30);
        assert_eq!(m.get(&key(10)), Some(&[10][..]));
        assert!(m.remove(&key(10)));
        assert_eq!(m.len(), 29);
        assert!(m.get(&key(10)).is_none());
        // Not a commitment in this mode.
        assert_eq!(m.root(), Digest([0; 32]));
    }

    #[test]
    fn blake3_count_matches_blake3_root() {
        let mut a = HashedMap::with_hash(TreapHash::Blake3);
        let mut b = HashedMap::with_hash(TreapHash::Blake3Count);
        for k in 0u8..20 {
            a.upsert(&key(k), &[k]);
            b.upsert(&key(k), &[k]);
        }
        assert_eq!(a.root(), b.root());
        let _ = take_treap_hash_calls();
        b.upsert(&key(21), &[21]);
        let calls = take_treap_hash_calls();
        assert!(calls.blake3() > 0);
        assert!(calls.node > 0);
        assert!(calls.prio >= 1);
    }

    #[test]
    fn empty_digest_is_cached_same_bytes() {
        let cached = empty_digest();
        let direct = Digest::from_bytes(&[], TREAP_EMPTY_DOMAIN);
        assert_eq!(cached, direct);
        assert_eq!(empty_digest(), cached);
    }
}
