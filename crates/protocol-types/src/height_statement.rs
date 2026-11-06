//! Public statement of a height: `C' = Commit(F(Open(C), I))` (ADR 0011).
//!
//! This is the instance `π` would prove. It is **not** `π`. `pre_root` is `C`
//! (parent height's treap `state_root`); `post_root` is `C'` (this height's
//! `ConsensusValue.state_root`). `C` is not a field of [`ConsensusValue`].

use crate::codec::{CanonicalEncode, EncodeBuf, ENCODING_VERSION};
use crate::ids::Bytes32;
use crate::order::Height;
use crate::ConsensusValue;

/// Light-client instance for a decided height. Native check needs `Open(C)`
/// and `I` (FULL_VIEW). Light clients would verify `π` against these bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HeightStatement {
    pub parent: Bytes32,
    pub height: Height,
    /// `C` — treap root before `F`. Not in [`ConsensusValue`].
    pub pre_root: Bytes32,
    pub input_commitment: Bytes32,
    /// `C'` — treap root after `F`. Voted as `ConsensusValue.state_root`.
    pub post_root: Bytes32,
    pub settlement_commitment: Bytes32,
}

impl HeightStatement {
    pub fn from_value(pre_root: Bytes32, value: &ConsensusValue) -> Self {
        Self {
            parent: value.parent,
            height: value.height,
            pre_root,
            input_commitment: value.input_commitment,
            post_root: value.state_root,
            settlement_commitment: value.settlement_commitment,
        }
    }

    /// The voted bundle is this transition's public `C'`, `I`, and deltas.
    /// Does not run `F`. Does not check `pre_root`.
    pub fn binds_value(&self, value: &ConsensusValue) -> bool {
        self.parent == value.parent
            && self.height == value.height
            && self.post_root == value.state_root
            && self.input_commitment == value.input_commitment
            && self.settlement_commitment == value.settlement_commitment
    }
}

impl CanonicalEncode for HeightStatement {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"HSTMT\0\0\0");
        buf.u16(ENCODING_VERSION);
        self.parent.encode(buf);
        self.height.encode(buf);
        self.pre_root.encode(buf);
        self.input_commitment.encode(buf);
        self.post_root.encode(buf);
        self.settlement_commitment.encode(buf);
    }
}
