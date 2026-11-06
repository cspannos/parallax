//! Little-endian canonical decoding. Inverse of [`EncodeBuf`].

use super::codec::ENCODING_VERSION;
use super::{
    AssetId, Bytes32, CanonicalEncode, ConsensusValue, EncodeBuf, Height, HeightStatement, Input,
    Instrument, InstrumentId, Order, OrderId, OwnerId, Price, Qty, SettlementDelta, Side, TimeSeq,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    TrailingBytes,
    UnknownTag,
    InvalidSide,
    EncodingVersion,
}

pub struct DecodeBuf<'a> {
    rest: &'a [u8],
}

impl<'a> DecodeBuf<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub fn remaining(&self) -> usize {
        self.rest.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.rest.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(b);
        Ok(u32::from_le_bytes(arr))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.take(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(u64::from_le_bytes(arr))
    }

    pub fn u128(&mut self) -> Result<u128, DecodeError> {
        let b = self.take(16)?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(b);
        Ok(u128::from_le_bytes(arr))
    }

    pub fn bytes_fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let b = self.take(N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(b);
        Ok(arr)
    }

    pub fn expect_tag(&mut self, tag: [u8; 8]) -> Result<(), DecodeError> {
        let got = self.bytes_fixed::<8>()?;
        if got != tag {
            return Err(DecodeError::UnknownTag);
        }
        Ok(())
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated canonical encoding"),
            Self::TrailingBytes => write!(f, "trailing bytes after canonical value"),
            Self::UnknownTag => write!(f, "unknown canonical tag"),
            Self::InvalidSide => write!(f, "invalid side"),
            Self::EncodingVersion => write!(f, "unsupported encoding version"),
        }
    }
}

impl std::error::Error for DecodeError {}

pub trait CanonicalDecode: Sized {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError>;

    fn decode_slice(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut buf = DecodeBuf::new(bytes);
        let value = Self::decode(&mut buf)?;
        if !buf.is_empty() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(value)
    }
}

impl CanonicalDecode for OrderId {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        Ok(Self(buf.bytes_fixed()?))
    }
}

impl CanonicalDecode for OwnerId {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        Ok(Self(buf.bytes_fixed()?))
    }
}

impl CanonicalDecode for InstrumentId {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        Ok(Self(buf.u32()?))
    }
}

impl CanonicalDecode for AssetId {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        Ok(Self(buf.u32()?))
    }
}

impl CanonicalDecode for Qty {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        Ok(Self(buf.u64()?))
    }
}

impl CanonicalDecode for Price {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        Ok(Self(buf.u64()?))
    }
}

impl CanonicalDecode for Height {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        Ok(Self(buf.u64()?))
    }
}

impl CanonicalDecode for TimeSeq {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        Ok(Self(buf.u64()?))
    }
}

impl CanonicalDecode for Side {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        match buf.u8()? {
            0 => Ok(Self::Buy),
            1 => Ok(Self::Sell),
            _ => Err(DecodeError::InvalidSide),
        }
    }
}

impl CanonicalDecode for Instrument {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        buf.expect_tag(*b"INSTR\0\0\0")?;
        Ok(Self {
            id: InstrumentId::decode(buf)?,
            base: AssetId::decode(buf)?,
            quote: AssetId::decode(buf)?,
            lot_size: Qty::decode(buf)?,
            tick_size: Price::decode(buf)?,
        })
    }
}

impl CanonicalDecode for Order {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        buf.expect_tag(*b"ORDER\0\0\0")?;
        Ok(Self {
            order_id: OrderId::decode(buf)?,
            instrument: InstrumentId::decode(buf)?,
            side: Side::decode(buf)?,
            quantity: Qty::decode(buf)?,
            limit_price: Price::decode(buf)?,
            owner: OwnerId::decode(buf)?,
            expiry: Height::decode(buf)?,
            nonce: buf.u64()?,
        })
    }
}

impl CanonicalDecode for Input {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        let tag = buf.bytes_fixed::<8>()?;
        match &tag {
            b"INPLACE\0" => Ok(Self::Place(Order::decode(buf)?)),
            b"INCNCL\0\0" => Ok(Self::Cancel {
                order_id: OrderId::decode(buf)?,
                owner: OwnerId::decode(buf)?,
                nonce: buf.u64()?,
            }),
            b"INADVH\0\0" => Ok(Self::AdvanceHeight {
                to: Height::decode(buf)?,
            }),
            _ => Err(DecodeError::UnknownTag),
        }
    }
}

impl CanonicalDecode for Bytes32 {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        Ok(Self(buf.bytes_fixed()?))
    }
}

impl CanonicalDecode for ConsensusValue {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        buf.expect_tag(*b"CVALUE\0\0")?;
        if buf.u16()? != ENCODING_VERSION {
            return Err(DecodeError::EncodingVersion);
        }
        Ok(Self {
            parent: Bytes32::decode(buf)?,
            height: Height::decode(buf)?,
            state_root: Bytes32::decode(buf)?,
            input_commitment: Bytes32::decode(buf)?,
            settlement_commitment: Bytes32::decode(buf)?,
        })
    }
}

impl CanonicalDecode for HeightStatement {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        buf.expect_tag(*b"HSTMT\0\0\0")?;
        if buf.u16()? != ENCODING_VERSION {
            return Err(DecodeError::EncodingVersion);
        }
        Ok(Self {
            parent: Bytes32::decode(buf)?,
            height: Height::decode(buf)?,
            pre_root: Bytes32::decode(buf)?,
            input_commitment: Bytes32::decode(buf)?,
            post_root: Bytes32::decode(buf)?,
            settlement_commitment: Bytes32::decode(buf)?,
        })
    }
}

impl CanonicalDecode for SettlementDelta {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        buf.expect_tag(*b"DELTA\0\0\0")?;
        Ok(Self {
            account: OwnerId::decode(buf)?,
            asset: AssetId::decode(buf)?,
            amount: buf.u128()?,
            debit: buf.u8()? != 0,
        })
    }
}

/// Versioned genesis blob stored in the WAL header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisBlob {
    pub height: Height,
    pub instruments: Vec<Instrument>,
}

impl CanonicalEncode for GenesisBlob {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"GENESIS\0");
        buf.u16(ENCODING_VERSION);
        self.height.encode(buf);
        buf.u32(self.instruments.len() as u32);
        for spec in &self.instruments {
            spec.encode(buf);
        }
    }
}

impl CanonicalDecode for GenesisBlob {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        buf.expect_tag(*b"GENESIS\0")?;
        if buf.u16()? != ENCODING_VERSION {
            return Err(DecodeError::EncodingVersion);
        }
        let height = Height::decode(buf)?;
        let n = buf.u32()? as usize;
        let mut instruments = Vec::with_capacity(n);
        for _ in 0..n {
            instruments.push(Instrument::decode(buf)?);
        }
        Ok(Self {
            height,
            instruments,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AssetId, CanonicalEncode, OwnerId, Qty, SettlementDelta};

    #[test]
    fn input_roundtrip() {
        let order = Order {
            order_id: OrderId::from_u128(9),
            instrument: InstrumentId(1),
            side: Side::Sell,
            quantity: Qty(3),
            limit_price: Price(7),
            owner: OwnerId::from_byte(2),
            expiry: Height(100),
            nonce: 4,
        };
        let inputs = [
            Input::Place(order),
            Input::Cancel {
                order_id: OrderId::from_u128(9),
                owner: OwnerId::from_byte(2),
                nonce: 5,
            },
            Input::AdvanceHeight { to: Height(2) },
        ];
        for i in inputs {
            let bytes = i.encode_vec();
            assert_eq!(Input::decode_slice(&bytes).unwrap(), i);
        }
    }

    #[test]
    fn truncated_is_error() {
        assert_eq!(Input::decode_slice(&[1, 2, 3]), Err(DecodeError::Truncated));
    }

    #[test]
    fn genesis_blob_roundtrip() {
        let blob = GenesisBlob {
            height: Height(1),
            instruments: vec![Instrument {
                id: InstrumentId(1),
                base: AssetId(1),
                quote: AssetId(2),
                lot_size: Qty(1),
                tick_size: Price(1),
            }],
        };
        let bytes = blob.encode_vec();
        assert_eq!(GenesisBlob::decode_slice(&bytes).unwrap(), blob);
    }

    #[test]
    fn consensus_value_roundtrip() {
        let v = ConsensusValue {
            parent: ConsensusValue::GENESIS_PARENT,
            height: Height(1),
            state_root: Bytes32([0x11; 32]),
            input_commitment: Bytes32([0x22; 32]),
            settlement_commitment: Bytes32([0x33; 32]),
        };
        let bytes = v.encode_vec();
        assert_eq!(ConsensusValue::decode_slice(&bytes).unwrap(), v);
    }

    #[test]
    fn height_statement_roundtrip_and_binds_value() {
        let v = ConsensusValue {
            parent: ConsensusValue::GENESIS_PARENT,
            height: Height(1),
            state_root: Bytes32([0x11; 32]),
            input_commitment: Bytes32([0x22; 32]),
            settlement_commitment: Bytes32([0x33; 32]),
        };
        let stmt = HeightStatement::from_value(Bytes32([0xaa; 32]), &v);
        assert!(stmt.binds_value(&v));
        assert_ne!(stmt.pre_root, stmt.post_root);
        let mut other = v;
        other.state_root = Bytes32([0xff; 32]);
        assert!(!stmt.binds_value(&other));
        let bytes = stmt.encode_vec();
        assert_eq!(HeightStatement::decode_slice(&bytes).unwrap(), stmt);
    }

    #[test]
    fn settlement_delta_roundtrip() {
        let d = SettlementDelta::debit(OwnerId::from_byte(3), AssetId(2), 99);
        let bytes = d.encode_vec();
        assert_eq!(SettlementDelta::decode_slice(&bytes).unwrap(), d);
    }
}
