use crate::codec::{CanonicalEncode, EncodeBuf};

/// Quantity in integer lots. Never a float.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Qty(pub u64);

impl Qty {
    pub const ZERO: Self = Self(0);

    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }

    pub fn saturating_min(self, other: Self) -> Self {
        Self(self.0.min(other.0))
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl CanonicalEncode for Qty {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.u64(self.0);
    }
}

/// Limit / fill price in integer ticks. Never a float.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Price(pub u64);

impl Price {
    pub const ZERO: Self = Self(0);

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl CanonicalEncode for Price {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.u64(self.0);
    }
}

/// Quote notional = qty lots × price ticks. Always fits in `u128`.
pub fn notional(qty: Qty, price: Price) -> u128 {
    u128::from(qty.0) * u128::from(price.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_product_fits_u128_not_i128() {
        let n = notional(Qty(u64::MAX), Price(u64::MAX));
        assert_eq!(n, u128::from(u64::MAX) * u128::from(u64::MAX));
        assert!(i128::try_from(n).is_err());
    }
}
