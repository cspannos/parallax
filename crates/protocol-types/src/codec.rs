//! Little-endian canonical encoding.
//!
//! Tags are 8-byte ASCII, NUL-padded. Integers are little-endian. There is no
//! padding between fields. `ENCODING_VERSION` is written by the hasher at the
//! start of a state commitment, not on every field.

pub const ENCODING_VERSION: u16 = 1;

#[derive(Clone, Debug, Default)]
pub struct EncodeBuf {
    inner: Vec<u8>,
}

impl EncodeBuf {
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: Vec::with_capacity(cap),
        }
    }

    pub fn u8(&mut self, v: u8) {
        self.inner.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.inner.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.inner.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.inner.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u128(&mut self, v: u128) {
        self.inner.extend_from_slice(&v.to_le_bytes());
    }

    pub fn bytes(&mut self, v: &[u8]) {
        self.inner.extend_from_slice(v);
    }

    pub fn tag(&mut self, tag: [u8; 8]) {
        self.inner.extend_from_slice(&tag);
    }

    pub fn encode<T: CanonicalEncode>(&mut self, value: &T) {
        value.encode(self);
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.inner
    }
}

pub trait CanonicalEncode {
    fn encode(&self, buf: &mut EncodeBuf);

    fn encode_vec(&self) -> Vec<u8> {
        let mut buf = EncodeBuf::new();
        self.encode(&mut buf);
        buf.into_vec()
    }
}

impl CanonicalEncode for u8 {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.u8(*self);
    }
}

impl CanonicalEncode for u64 {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.u64(*self);
    }
}
