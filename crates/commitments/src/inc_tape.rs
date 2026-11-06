//! A tape of treap steps across the three INC maps (general `C'` update, B3).
//!
//! [`IncTape::verify`] opens the pre INC root from a header and three map
//! roots, applies each [`TreapStep`] to its map, and closes the post INC root.
//! It also returns a commitment to the op list. It proves "these map ops take
//! `C` to `C'`". It does **not** prove that `F` (matching) chose those ops, nor
//! how `height` / `next_time` moved: the post header is a witness, bound only
//! through the post root.
//!
//! Byte encodings here are a witness format (zkVM input), not a wire format.

use protocol_types::ENCODING_VERSION;

use crate::treap_witness::{StepRoots, TreapOp, TreapStep, WitnessError, WitnessNode};
use crate::{Digest, TreapHash, INC_DOMAIN};

pub const MAP_NONCES: u8 = 0;
pub const MAP_SEEN: u8 = 1;
pub const MAP_RESTING: u8 = 2;

/// Domain of [`TapeClaim::ops`].
pub const INC_OPS_DOMAIN: &[u8] = b"plx/clob/inc-ops/v1";

/// The non-map fields of the INC root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncHeader {
    pub height: u64,
    pub next_time: u64,
    pub instruments: Digest,
}

/// `clob::IncrementalState::root` under the production `C'` hash.
pub fn inc_root(h: &IncHeader, maps: &[Digest; 3]) -> Digest {
    inc_root_with(TreapHash::default(), h, maps)
}

/// `clob::IncrementalState::root_preimage`.
pub fn inc_root_preimage(h: &IncHeader, maps: &[Digest; 3]) -> Vec<u8> {
    let mut pre = Vec::with_capacity(244);
    pre.extend_from_slice(INC_DOMAIN);
    pre.extend_from_slice(&ENCODING_VERSION.to_le_bytes());
    let mut field = |tag: &[u8], bytes: &[u8]| {
        pre.extend_from_slice(tag);
        pre.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        pre.extend_from_slice(bytes);
    };
    field(b"height", &h.height.to_le_bytes());
    field(b"next_t", &h.next_time.to_le_bytes());
    field(b"instrs", &h.instruments.0);
    field(b"nonces", &maps[0].0);
    field(b"seenid", &maps[1].0);
    field(b"books", &maps[2].0);
    pre
}

/// INC root under a `C'` hash mode (BLAKE3 or SHA-256 of the same preimage).
pub fn inc_root_with(mode: TreapHash, h: &IncHeader, maps: &[Digest; 3]) -> Digest {
    let pre = inc_root_preimage(h, maps);
    if mode == TreapHash::Sha256 {
        return Digest(crate::hashed_map::sha256_once(&pre));
    }
    Digest(*blake3::hash(&pre).as_bytes())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncTape {
    /// `C'` hash mode of the maps and the INC root (BLAKE3 or SHA-256).
    pub hash: TreapHash,
    pub pre: IncHeader,
    pub pre_maps: [Digest; 3],
    /// `(map, step)` in apply order.
    pub steps: Vec<(u8, TreapStep)>,
    pub post: IncHeader,
}

/// What a valid tape proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TapeClaim {
    pub pre_root: Digest,
    pub post_root: Digest,
    /// BLAKE3 of the op list under [`INC_OPS_DOMAIN`].
    pub ops: Digest,
    pub steps: usize,
    pub node_hashes: usize,
    pub prio_hashes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TapeError {
    Step { index: usize, error: WitnessError },
    MapId { index: usize },
    /// Instruments are fixed at genesis; a tape may not change them.
    Instruments,
    Decode,
    /// Only [`TreapHash::Blake3`] and [`TreapHash::Sha256`] are commitments.
    HashMode,
}

impl IncTape {
    pub fn verify(&self) -> Result<TapeClaim, TapeError> {
        if !matches!(self.hash, TreapHash::Blake3 | TreapHash::Sha256) {
            return Err(TapeError::HashMode);
        }
        if self.pre.instruments != self.post.instruments {
            return Err(TapeError::Instruments);
        }
        let mut maps = self.pre_maps;
        let mut ops = blake3::Hasher::new();
        ops.update(INC_OPS_DOMAIN);
        ops.update(&ENCODING_VERSION.to_le_bytes());
        ops.update(&(self.steps.len() as u64).to_le_bytes());
        let (mut node_hashes, mut prio_hashes) = (0, 0);
        for (index, (map, step)) in self.steps.iter().enumerate() {
            let slot = maps
                .get_mut(*map as usize)
                .ok_or(TapeError::MapId { index })?;
            let StepRoots { old, new, node_hashes: n, prio_hashes: p } =
                step.verify_with(self.hash).map_err(|error| TapeError::Step { index, error })?;
            if old != *slot {
                return Err(TapeError::Step { index, error: WitnessError::OldRoot });
            }
            *slot = new;
            node_hashes += n;
            prio_hashes += p;
            ops.update(&[*map]);
            encode_op(&step.op, &mut |b| {
                ops.update(b);
            });
        }
        Ok(TapeClaim {
            pre_root: inc_root_with(self.hash, &self.pre, &self.pre_maps),
            post_root: inc_root_with(self.hash, &self.post, &maps),
            ops: Digest(*ops.finalize().as_bytes()),
            steps: self.steps.len(),
            node_hashes,
            prio_hashes,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = |b: &[u8]| out.extend_from_slice(b);
        w(&[u8::from(self.hash == TreapHash::Sha256)]);
        encode_header(&self.pre, &mut w);
        for m in &self.pre_maps {
            w(&m.0);
        }
        encode_header(&self.post, &mut w);
        w(&(self.steps.len() as u32).to_le_bytes());
        for (map, step) in &self.steps {
            w(&[*map]);
            encode_op(&step.op, &mut w);
            w(&(step.insert_at as u32).to_le_bytes());
            for list in [&step.path, &step.left_spine, &step.right_spine] {
                w(&(list.len() as u32).to_le_bytes());
                for n in list {
                    w(&n.left.0);
                    w(&n.right.0);
                    encode_bytes(&n.key, &mut w);
                    encode_bytes(&n.value, &mut w);
                }
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TapeError> {
        let mut r = Reader(bytes);
        let hash = match r.take(1)?[0] {
            0 => TreapHash::Blake3,
            1 => TreapHash::Sha256,
            _ => return Err(TapeError::Decode),
        };
        let pre = r.header()?;
        let pre_maps = [r.digest()?, r.digest()?, r.digest()?];
        let post = r.header()?;
        let n = r.u32()? as usize;
        let mut steps = Vec::with_capacity(n.min(1 << 20));
        for _ in 0..n {
            let map = r.take(1)?[0];
            let kind = r.take(1)?[0];
            let key = r.bytes()?;
            let value = r.bytes()?;
            let op = match kind {
                0 => TreapOp::Upsert { key, value },
                1 if value.is_empty() => TreapOp::Remove { key },
                _ => return Err(TapeError::Decode),
            };
            let insert_at = r.u32()? as usize;
            let mut lists: [Vec<WitnessNode>; 3] = Default::default();
            for list in &mut lists {
                let len = r.u32()? as usize;
                for _ in 0..len {
                    let left = r.digest()?;
                    let right = r.digest()?;
                    let key = r.bytes()?;
                    let value = r.bytes()?;
                    list.push(WitnessNode { key, value, left, right });
                }
            }
            let [path, left_spine, right_spine] = lists;
            steps.push((map, TreapStep { op, path, insert_at, left_spine, right_spine }));
        }
        if !r.0.is_empty() {
            return Err(TapeError::Decode);
        }
        Ok(IncTape { hash, pre, pre_maps, steps, post })
    }
}

fn encode_header(h: &IncHeader, w: &mut impl FnMut(&[u8])) {
    w(&h.height.to_le_bytes());
    w(&h.next_time.to_le_bytes());
    w(&h.instruments.0);
}

fn encode_bytes(b: &[u8], w: &mut impl FnMut(&[u8])) {
    w(&(b.len() as u32).to_le_bytes());
    w(b);
}

/// `kind ‖ len ‖ key ‖ len ‖ value`; remove has an empty value.
fn encode_op(op: &TreapOp, w: &mut impl FnMut(&[u8])) {
    match op {
        TreapOp::Upsert { key, value } => {
            w(&[0]);
            encode_bytes(key, w);
            encode_bytes(value, w);
        }
        TreapOp::Remove { key } => {
            w(&[1]);
            encode_bytes(key, w);
            encode_bytes(&[], w);
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TapeError> {
        if self.0.len() < n {
            return Err(TapeError::Decode);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }

    fn u32(&mut self) -> Result<u32, TapeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, TapeError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn digest(&mut self) -> Result<Digest, TapeError> {
        Ok(Digest(self.take(32)?.try_into().unwrap()))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, TapeError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }

    fn header(&mut self) -> Result<IncHeader, TapeError> {
        Ok(IncHeader {
            height: self.u64()?,
            next_time: self.u64()?,
            instruments: self.digest()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HashedMap;

    fn header(t: u64) -> IncHeader {
        IncHeader { height: 1, next_time: t, instruments: Digest([5; 32]) }
    }

    #[test]
    fn tape_round_trips_and_chains_maps() {
        let mut maps = [HashedMap::new(), HashedMap::new(), HashedMap::new()];
        for i in 0..200u32 {
            maps[(i % 3) as usize].upsert(&i.to_be_bytes(), &[i as u8; 9]);
        }
        let pre_maps = [maps[0].root(), maps[1].root(), maps[2].root()];
        let mut steps = Vec::new();
        for i in 0..60u32 {
            let m = (i % 3) as usize;
            let key = (i * 7 % 300).to_be_bytes();
            let step = if i % 4 == 3 {
                let s = maps[m].remove_step(&key);
                maps[m].remove(&key);
                s
            } else {
                let s = maps[m].upsert_step(&key, &[1, 2, 3]);
                maps[m].upsert(&key, &[1, 2, 3]);
                s
            };
            steps.push((m as u8, step));
        }
        let tape = IncTape { hash: TreapHash::default(), pre: header(3), pre_maps, steps, post: header(9) };
        let claim = tape.verify().unwrap();
        assert_eq!(claim.pre_root, inc_root(&header(3), &pre_maps));
        let post_maps = [maps[0].root(), maps[1].root(), maps[2].root()];
        assert_eq!(claim.post_root, inc_root(&header(9), &post_maps));
        assert_eq!(IncTape::decode(&tape.encode()), Ok(tape.clone()));

        let mut bad = tape.clone();
        bad.steps.swap(0, 3);
        assert!(matches!(bad.verify(), Err(TapeError::Step { .. })) || bad.verify().unwrap().post_root != claim.post_root);
        let mut bad = tape.clone();
        bad.steps[5].0 = 3;
        assert_eq!(bad.verify().err(), Some(TapeError::MapId { index: 5 }));
        let mut bad = tape;
        bad.post.instruments = Digest([6; 32]);
        assert_eq!(bad.verify().err(), Some(TapeError::Instruments));
    }
}
