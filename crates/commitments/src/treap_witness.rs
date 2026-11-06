//! Path witness for one treap mutation (general `C'` update, phase B1).
//!
//! A [`TreapStep`] carries only the nodes one `upsert` or `remove` reads, each
//! with both child hashes as they were before the step. [`TreapStep::verify`]
//! recomputes the old root and the new root from that witness alone: no tree,
//! no rotations. An insert is a split of the search path below the insertion
//! depth; a remove is a merge of two spines. Because the treap shape is unique
//! for a key set (priority = hash of key), this gives the same root as
//! [`crate::HashedMap`]'s rotate-based walk.
//!
//! This is the reference semantics a general (not fixture-shaped) treap-update
//! AIR has to match. It is not a STARK and it is not `F`.
//!
//! Soundness relies on the old root committing a valid treap (BST order and
//! heap order). That holds by induction when every step from the empty map is
//! checked; the witness does not re-prove it.

use std::cmp::Ordering;

use crate::{
    priority_u64_with, treap_empty_digest_with, treap_node_hash_with, Digest, TreapHash,
};

/// One treap node as the step reads it, with both child hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessNode {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub left: Digest,
    pub right: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreapOp {
    Upsert { key: Vec<u8>, value: Vec<u8> },
    Remove { key: Vec<u8> },
}

impl TreapOp {
    pub fn key(&self) -> &[u8] {
        match self {
            TreapOp::Upsert { key, .. } | TreapOp::Remove { key } => key,
        }
    }
}

/// Witness for one mutation against one map root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreapStep {
    pub op: TreapOp,
    /// Search path, root first. Ends at the node holding the key, or at the
    /// node whose child toward the key is empty. Empty iff the map is empty.
    pub path: Vec<WitnessNode>,
    /// Insert only: depth where the new node goes (`0..=path.len()`).
    pub insert_at: usize,
    /// Remove only: right spine of the removed node's left subtree, top first.
    pub left_spine: Vec<WitnessNode>,
    /// Remove only: left spine of the removed node's right subtree, top first.
    pub right_spine: Vec<WitnessNode>,
}

/// Roots implied by a valid witness, and the hashes it took to check them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepRoots {
    pub old: Digest,
    pub new: Digest,
    /// `node_digest` evaluations (old side + new side).
    pub node_hashes: usize,
    /// Priority hashes (`TREAP_PRIO_DOMAIN || key`).
    pub prio_hashes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessError {
    /// A path node's child toward the key is not the next path node.
    PathLink { depth: usize },
    /// The path stops at a node that neither holds the key nor has an empty
    /// child toward it, or passes through the key before its end.
    PathEnd,
    /// `insert_at` is out of range or violates heap order.
    InsertDepth,
    /// Insert/remove-only fields are set on the wrong op.
    UnusedField,
    /// A spine does not rebuild the removed node's child.
    Spine,
    /// The witness is valid but its old root is not the expected one.
    OldRoot,
}

/// Heap order of the map: higher priority first, ties by smaller key.
fn heap_before(pa: u64, ka: &[u8], pb: u64, kb: &[u8]) -> bool {
    pa > pb || (pa == pb && ka < kb)
}

struct Counter {
    mode: TreapHash,
    node: usize,
    prio: usize,
}

impl Counter {
    fn node(&mut self, left: &Digest, key: &[u8], value: &[u8], right: &Digest) -> Digest {
        self.node += 1;
        treap_node_hash_with(self.mode, left, key, value, right)
    }

    fn prio(&mut self, key: &[u8]) -> u64 {
        self.prio += 1;
        priority_u64_with(self.mode, key)
    }
}

impl TreapStep {
    /// Check the witness and return the old and new roots it implies.
    pub fn verify(&self) -> Result<StepRoots, WitnessError> {
        self.verify_with(TreapHash::default())
    }

    /// [`Self::verify`] under a `C'` hash mode ([`TreapHash::Blake3`] or
    /// [`TreapHash::Sha256`]); must match the map the witness came from.
    pub fn verify_with(&self, mode: TreapHash) -> Result<StepRoots, WitnessError> {
        let key = self.op.key();
        let mut c = Counter { mode, node: 0, prio: 0 };
        let empty = treap_empty_digest_with(mode);

        // Old side: hash the path bottom-up, check every link and the search
        // direction, and find whether the path ends on the key.
        let d = self.path.len();
        let mut found = false;
        let mut old = empty;
        for (i, n) in self.path.iter().enumerate().rev() {
            let ord = key.cmp(n.key.as_slice());
            if i + 1 == d {
                match ord {
                    Ordering::Equal => found = true,
                    Ordering::Less if n.left == empty => {}
                    Ordering::Greater if n.right == empty => {}
                    _ => return Err(WitnessError::PathEnd),
                }
            } else {
                let toward = match ord {
                    Ordering::Less => &n.left,
                    Ordering::Greater => &n.right,
                    Ordering::Equal => return Err(WitnessError::PathEnd),
                };
                if *toward != old {
                    return Err(WitnessError::PathLink { depth: i });
                }
            }
            old = c.node(&n.left, &n.key, &n.value, &n.right);
        }

        let removing = matches!(self.op, TreapOp::Remove { .. });
        let inserting = !found && !removing;
        if !inserting && self.insert_at != 0 {
            return Err(WitnessError::UnusedField);
        }
        if !(removing && found) && !(self.left_spine.is_empty() && self.right_spine.is_empty()) {
            return Err(WitnessError::UnusedField);
        }

        // New side: the hash that replaces the subtree rooted at `from`, then
        // rehash the untouched ancestors above it.
        let (from, sub) = match &self.op {
            TreapOp::Upsert { value, .. } if found => {
                let n = &self.path[d - 1];
                (d - 1, c.node(&n.left, &n.key, value, &n.right))
            }
            TreapOp::Upsert { value, .. } => {
                let k = self.insert_at;
                if k > d {
                    return Err(WitnessError::InsertDepth);
                }
                let p = c.prio(key);
                if k > 0 {
                    let a = &self.path[k - 1];
                    if !heap_before(c.prio(&a.key), &a.key, p, key) {
                        return Err(WitnessError::InsertDepth);
                    }
                }
                if k < d {
                    let b = &self.path[k];
                    if !heap_before(p, key, c.prio(&b.key), &b.key) {
                        return Err(WitnessError::InsertDepth);
                    }
                }
                // Split path[k..] by key: smaller keys chain down the new
                // node's left via their right child, larger keys down its right
                // via their left child. Off-path children are unchanged.
                let (mut l, mut r) = (empty, empty);
                for n in self.path[k..].iter().rev() {
                    if n.key.as_slice() < key {
                        l = c.node(&n.left, &n.key, &n.value, &l);
                    } else {
                        r = c.node(&r, &n.key, &n.value, &n.right);
                    }
                }
                (k, c.node(&l, key, value, &r))
            }
            TreapOp::Remove { .. } if found => {
                let n = &self.path[d - 1];
                let a = rebuild_spine(&self.left_spine, n.left, Side::Right, &mut c)?;
                let b = rebuild_spine(&self.right_spine, n.right, Side::Left, &mut c)?;
                (d - 1, merge(&self.left_spine, &a, &self.right_spine, &b, &mut c))
            }
            TreapOp::Remove { .. } => return Ok(StepRoots { old, new: old, node_hashes: c.node, prio_hashes: c.prio }),
        };

        let mut new = sub;
        for n in self.path[..from].iter().rev() {
            new = if key < n.key.as_slice() {
                c.node(&new, &n.key, &n.value, &n.right)
            } else {
                c.node(&n.left, &n.key, &n.value, &new)
            };
        }
        Ok(StepRoots { old, new, node_hashes: c.node, prio_hashes: c.prio })
    }

    /// [`Self::verify`] and require that the witness opens `old_root`.
    pub fn apply(&self, old_root: Digest) -> Result<Digest, WitnessError> {
        self.apply_with(TreapHash::default(), old_root)
    }

    /// [`Self::apply`] under a `C'` hash mode.
    pub fn apply_with(&self, mode: TreapHash, old_root: Digest) -> Result<Digest, WitnessError> {
        let roots = self.verify_with(mode)?;
        if roots.old != old_root {
            return Err(WitnessError::OldRoot);
        }
        Ok(roots.new)
    }
}

#[derive(Clone, Copy)]
enum Side {
    Left,
    Right,
}

/// Hash a spine bottom-up and check it rebuilds `top`. Returns each spine
/// node's subtree hash, top first. The spine follows `side` children; the last
/// node's `side` child is empty.
fn rebuild_spine(
    spine: &[WitnessNode],
    top: Digest,
    side: Side,
    c: &mut Counter,
) -> Result<Vec<Digest>, WitnessError> {
    let empty = treap_empty_digest_with(c.mode);
    let mut hashes = vec![empty; spine.len()];
    let mut below = empty;
    for (j, n) in spine.iter().enumerate().rev() {
        let next = match side {
            Side::Left => &n.left,
            Side::Right => &n.right,
        };
        if *next != below {
            return Err(WitnessError::Spine);
        }
        below = c.node(&n.left, &n.key, &n.value, &n.right);
        hashes[j] = below;
    }
    if below != top {
        return Err(WitnessError::Spine);
    }
    Ok(hashes)
}

/// Treap merge of `a` (all keys smaller) and `b`, walking `a`'s right spine
/// and `b`'s left spine. `ha[i]` / `hb[j]` are the original subtree hashes.
fn merge(
    a: &[WitnessNode],
    ha: &[Digest],
    b: &[WitnessNode],
    hb: &[Digest],
    c: &mut Counter,
) -> Digest {
    let empty = treap_empty_digest_with(c.mode);
    // Decide the interleaving top-down, then hash bottom-up.
    let pa: Vec<u64> = a.iter().map(|n| c.prio(&n.key)).collect();
    let pb: Vec<u64> = b.iter().map(|n| c.prio(&n.key)).collect();
    let (mut i, mut j) = (0, 0);
    let mut order = Vec::new();
    while i < a.len() && j < b.len() {
        if heap_before(pa[i], &a[i].key, pb[j], &b[j].key) {
            order.push((true, i));
            i += 1;
        } else {
            order.push((false, j));
            j += 1;
        }
    }
    let mut h = if i < a.len() {
        ha[i]
    } else if j < b.len() {
        hb[j]
    } else {
        empty
    };
    for &(from_a, k) in order.iter().rev() {
        h = if from_a {
            let n = &a[k];
            c.node(&n.left, &n.key, &n.value, &h)
        } else {
            let n = &b[k];
            c.node(&h, &n.key, &n.value, &n.right)
        };
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HashedMap;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    fn key_of(id: u64, len: usize) -> Vec<u8> {
        id.to_be_bytes().iter().cycle().take(len).copied().collect()
    }

    /// Witness roots equal the map's roots before and after every op.
    fn check_step(m: &mut HashedMap, op: TreapOp) -> StepRoots {
        let step = match &op {
            TreapOp::Upsert { key, value } => m.upsert_step(key, value),
            TreapOp::Remove { key } => m.remove_step(key),
        };
        let roots = step.verify_with(m.hash_mode()).expect("valid witness");
        assert_eq!(roots.old, m.root(), "old root");
        match op {
            TreapOp::Upsert { key, value } => m.upsert(&key, &value),
            TreapOp::Remove { key } => {
                m.remove(&key);
            }
        }
        assert_eq!(roots.new, m.root(), "new root");
        roots
    }

    #[test]
    fn insert_into_empty_and_singleton() {
        let mut m = HashedMap::new();
        check_step(&mut m, TreapOp::Upsert { key: b"b".to_vec(), value: b"1".to_vec() });
        check_step(&mut m, TreapOp::Upsert { key: b"a".to_vec(), value: b"2".to_vec() });
        check_step(&mut m, TreapOp::Upsert { key: b"c".to_vec(), value: b"3".to_vec() });
        check_step(&mut m, TreapOp::Remove { key: b"b".to_vec() });
        check_step(&mut m, TreapOp::Remove { key: b"zz".to_vec() });
        check_step(&mut m, TreapOp::Remove { key: b"a".to_vec() });
        check_step(&mut m, TreapOp::Remove { key: b"c".to_vec() });
        assert!(m.is_empty());
    }

    #[test]
    fn random_ops_match_map() {
        for mode in [TreapHash::Blake3, TreapHash::Sha256] {
            random_ops_match_map_with(mode);
        }
    }

    fn random_ops_match_map_with(mode: TreapHash) {
        for (seed, key_len) in [(1u64, 1usize), (2, 8), (3, 16), (4, 3)] {
            let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed);
            let mut m = HashedMap::with_hash(mode);
            let mut live: Vec<Vec<u8>> = Vec::new();
            for step in 0..3000 {
                let roll = rng.below(10);
                let op = if roll < 5 || live.is_empty() {
                    let k = key_of(rng.next() % 4000, key_len);
                    TreapOp::Upsert { key: k, value: vec![(step % 251) as u8; rng.below(40)] }
                } else if roll < 7 {
                    let k = live[rng.below(live.len())].clone();
                    TreapOp::Upsert { key: k, value: vec![7; rng.below(9)] }
                } else if roll < 9 {
                    TreapOp::Remove { key: live[rng.below(live.len())].clone() }
                } else {
                    TreapOp::Remove { key: key_of(rng.next() % 4000, key_len) }
                };
                check_step(&mut m, op.clone());
                match op {
                    TreapOp::Upsert { key, .. } => {
                        if !live.contains(&key) {
                            live.push(key);
                        }
                    }
                    TreapOp::Remove { key } => live.retain(|k| *k != key),
                }
            }
            assert_eq!(m.len(), live.len());
        }
    }

    fn map_8k() -> HashedMap {
        let mut m = HashedMap::new();
        for id in 0..8_000u64 {
            m.upsert(&key_of(id * 2, 16), &[1; 200]);
        }
        m
    }

    /// Witness cost at 8k, 16-byte keys (OrderId-shaped), 200 B values.
    #[test]
    fn witness_cost_at_8k() {
        let mut m = map_8k();
        let mut rng = Rng(77);
        let (mut ins, mut rem, mut upd) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..500 {
            let odd = key_of(rng.next() % 16_000 | 1, 16);
            ins.push(check_step(&mut m, TreapOp::Upsert { key: odd.clone(), value: vec![2; 200] }));
            upd.push(check_step(&mut m, TreapOp::Upsert { key: odd.clone(), value: vec![3; 200] }));
            rem.push(check_step(&mut m, TreapOp::Remove { key: odd }));
        }
        for (name, v) in [("insert", &ins), ("update", &upd), ("remove", &rem)] {
            let n: Vec<usize> = v.iter().map(|r| r.node_hashes).collect();
            let p: Vec<usize> = v.iter().map(|r| r.prio_hashes).collect();
            let mean = |x: &[usize]| x.iter().sum::<usize>() as f64 / x.len() as f64;
            eprintln!(
                "treap witness {name} at 8k: node mean {:.1} max {}, prio mean {:.1} max {}",
                mean(&n),
                n.iter().max().unwrap(),
                mean(&p),
                p.iter().max().unwrap()
            );
        }
    }

    #[test]
    fn hash_modes_commit_differently() {
        let (mut a, mut b) = (HashedMap::with_hash(TreapHash::Blake3), HashedMap::new());
        assert_ne!(a.root(), b.root(), "empty roots differ");
        for k in 0u8..50 {
            a.upsert(&[k], &[k]);
            b.upsert(&[k], &[k]);
        }
        assert_ne!(a.root(), b.root());
        // A BLAKE3 witness does not verify as SHA-256 (and vice versa).
        let step = b.upsert_step(&[200], &[1]);
        assert_eq!(step.apply_with(TreapHash::Sha256, b.root()).is_ok(), true);
        assert!(step.apply_with(TreapHash::Blake3, b.root()).is_err());
    }

    #[test]
    fn tampered_witness_rejected() {
        let m = map_8k();
        let key = key_of(4001, 16);
        let good = m.upsert_step(&key, &[9; 200]);
        assert!(good.verify().is_ok());
        assert!(good.path.len() > 3);

        // On-path child wrong: the link check fails.
        let mid = good.path.len() / 2;
        let mut t = good.clone();
        t.path[mid].left.0[0] ^= 1;
        t.path[mid].right.0[0] ^= 1;
        assert_eq!(t.verify().err(), Some(WitnessError::PathLink { depth: mid }));
        // Off-path child wrong: the parent's link fails; at the root, the
        // witness is self-consistent but opens a different root.
        let flip_off_path = |t: &mut TreapStep, i: usize| {
            if key.as_slice() < t.path[i].key.as_slice() {
                t.path[i].right.0[0] ^= 1;
            } else {
                t.path[i].left.0[0] ^= 1;
            }
        };
        let mut t = good.clone();
        flip_off_path(&mut t, mid);
        assert_eq!(t.verify().err(), Some(WitnessError::PathLink { depth: mid - 1 }));
        let mut t = good.clone();
        flip_off_path(&mut t, 0);
        assert!(t.verify().is_ok());
        assert_eq!(t.apply(m.root()).err(), Some(WitnessError::OldRoot));

        let mut t = good.clone();
        t.path.pop();
        assert_eq!(t.verify().err(), Some(WitnessError::PathEnd));

        for k in [good.insert_at.wrapping_sub(1), good.insert_at + 1] {
            let mut t = good.clone();
            t.insert_at = k;
            assert!(t.verify().is_err(), "insert_at {k}");
        }


        let present = key_of(4000, 16);
        let good = m.remove_step(&present);
        assert!(good.verify().is_ok());
        if !good.left_spine.is_empty() {
            let mut t = good.clone();
            t.left_spine.pop();
            assert_eq!(t.verify().err(), Some(WitnessError::Spine));
        }
        let mut t = good.clone();
        t.right_spine.push(t.path[0].clone());
        assert_eq!(t.verify().err(), Some(WitnessError::Spine));
        let mut t = good;
        t.insert_at = 1;
        assert_eq!(t.verify().err(), Some(WitnessError::UnusedField));
    }
}
