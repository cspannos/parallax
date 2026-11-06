use crate::codec::{CanonicalEncode, EncodeBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OrderId(pub [u8; 16]);

impl OrderId {
    pub const ZERO: Self = Self([0u8; 16]);

    pub fn from_u128(v: u128) -> Self {
        Self(v.to_le_bytes())
    }
}

impl CanonicalEncode for OrderId {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.bytes(&self.0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnerId(pub [u8; 32]);

impl OwnerId {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn from_byte(b: u8) -> Self {
        let mut id = [0u8; 32];
        id[0] = b;
        Self(id)
    }
}

impl CanonicalEncode for OwnerId {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.bytes(&self.0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstrumentId(pub u32);

impl CanonicalEncode for InstrumentId {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.u32(self.0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetId(pub u32);

impl CanonicalEncode for AssetId {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.u32(self.0);
    }
}

/// 32-byte commitment or value id. Hashing domain lives in `commitments`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes32(pub [u8; 32]);

impl Bytes32 {
    pub const ZERO: Self = Self([0u8; 32]);
}

impl CanonicalEncode for Bytes32 {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.bytes(&self.0);
    }
}
