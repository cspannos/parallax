//! M4a consensus value (ADR 0009). Not the engine. Not the book.

use crate::codec::{CanonicalEncode, EncodeBuf, ENCODING_VERSION};
use crate::ids::Bytes32;
use crate::order::Height;

/// Public bundle Malachite votes on in M4a.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConsensusValue {
    pub parent: Bytes32,
    pub height: Height,
    pub state_root: Bytes32,
    pub input_commitment: Bytes32,
    pub settlement_commitment: Bytes32,
}

impl ConsensusValue {
    pub const GENESIS_PARENT: Bytes32 = Bytes32::ZERO;
}

impl CanonicalEncode for ConsensusValue {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"CVALUE\0\0");
        buf.u16(ENCODING_VERSION);
        self.parent.encode(buf);
        self.height.encode(buf);
        self.state_root.encode(buf);
        self.input_commitment.encode(buf);
        self.settlement_commitment.encode(buf);
    }
}
