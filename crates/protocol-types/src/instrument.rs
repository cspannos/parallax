use crate::codec::{CanonicalEncode, EncodeBuf};
use crate::ids::{AssetId, InstrumentId};
use crate::qty::{Price, Qty};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instrument {
    pub id: InstrumentId,
    pub base: AssetId,
    pub quote: AssetId,
    pub lot_size: Qty,
    pub tick_size: Price,
}

impl CanonicalEncode for Instrument {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"INSTR\0\0\0");
        self.id.encode(buf);
        self.base.encode(buf);
        self.quote.encode(buf);
        self.lot_size.encode(buf);
        self.tick_size.encode(buf);
    }
}
