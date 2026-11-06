//! Hex helpers for the replica worker CLI. Not a general codec.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexError {
    OddLength,
    InvalidDigit,
}

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OddLength => write!(f, "odd hex length"),
            Self::InvalidDigit => write!(f, "invalid hex digit"),
        }
    }
}

impl std::error::Error for HexError {}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, HexError> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(HexError::OddLength);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i])?;
        let lo = nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn nibble(c: u8) -> Result<u8, HexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(HexError::InvalidDigit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let bytes = [0x00, 0xde, 0xad, 0x0f];
        assert_eq!(decode_hex(&encode_hex(&bytes)).unwrap(), bytes);
    }
}
