use {
    crate::{
        traits::{ByteOrder, FieldElement},
        utils::Choice,
    },
    core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[derive(Clone, Copy)]
pub struct Gf256(u8);

impl Gf256 {
    const POLYNOMIAL: u8 = 0x1b;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }

    fn mul(self, rhs: Self) -> Self {
        let mut a = self.0;
        let mut b = rhs.0;
        let mut r = 0u8;
        for _ in 0..8 {
            r ^= a & (b & 1).wrapping_neg();
            a = (a << 1) ^ (Self::POLYNOMIAL & (a >> 7).wrapping_neg());
            b >>= 1;
        }
        Self(r)
    }

    fn square(self) -> Self {
        self.mul(self)
    }

    fn invert(self) -> Self {
        let x = self;
        let x4 = x.square().square();
        let x8 = x4.square();
        let x9 = x8.mul(x);
        let x25 = x8.square().mul(x9);
        let x50 = x25.square();
        let x250 = x50.square().square().mul(x50);
        x250.mul(x4)
    }

    fn sqrt(self) -> Self {
        let mut x = self;
        for _ in 0..7 {
            x = x.square();
        }
        x
    }

    fn swap(a: &mut Self, b: &mut Self, condition: Choice) {
        let swapped = *a;
        *a = Self::select(a, b, condition);
        *b = Self::select(b, &swapped, condition);
    }

    fn select(a: &Self, b: &Self, condition: Choice) -> Self {
        Self(condition.select(a.0, b.0))
    }

    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::eq(self.0, other.0)
    }
}

impl Add for Gf256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl AddAssign for Gf256 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Sub for Gf256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl SubAssign for Gf256 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl Neg for Gf256 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Mul for Gf256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl MulAssign for Gf256 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl Div for Gf256 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.mul(rhs.invert())
    }
}

impl DivAssign for Gf256 {
    fn div_assign(&mut self, rhs: Self) {
        *self = self.div(rhs);
    }
}

impl From<[u8; 1]> for Gf256 {
    fn from(value: [u8; 1]) -> Self {
        Self(value[0])
    }
}

impl From<u32> for Gf256 {
    fn from(value: u32) -> Self {
        Self(value as u8)
    }
}

impl From<Gf256> for [u8; 1] {
    fn from(value: Gf256) -> Self {
        [value.0]
    }
}

impl FieldElement for Gf256 {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    const CAPACITY: usize = 8;
    const BYTE_ORDER: ByteOrder = ByteOrder::LittleEndian;

    type Bytes = [u8; 1];

    fn swap(a: &mut Self, b: &mut Self, condition: Choice) {
        Self::swap(a, b, condition);
    }

    fn select(a: &Self, b: &Self, condition: Choice) -> Self {
        Self::select(a, b, condition)
    }

    fn ct_eq(&self, other: &Self) -> Choice {
        self.ct_eq(other)
    }

    fn square(self) -> Self {
        self.square()
    }

    fn invert(self) -> Self {
        self.invert()
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        let valid = !b.ct_eq(&Self::ZERO);
        let r = self.div(b).sqrt();
        (Self::select(&Self::ZERO, &r, valid), valid)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::csprngs::Rng};

    fn mul_reference(a: u8, b: u8) -> u8 {
        let mut product = 0u16;
        for i in 0..8 {
            if (b >> i) & 1 == 1 {
                product ^= (a as u16) << i;
            }
        }
        for i in (8..16).rev() {
            if (product >> i) & 1 == 1 {
                product ^= 0x11b << (i - 8);
            }
        }
        product as u8
    }

    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf

    #[test]
    fn test_gf256_mul_fips197() {
        assert!((Gf256(0x57) * Gf256(0x83)).ct_eq(&Gf256(0xc1)).to_bool());
        assert!((Gf256(0x57) * Gf256(0x13)).ct_eq(&Gf256(0xfe)).to_bool());
        assert!((Gf256(0x53) * Gf256(0xca)).ct_eq(&Gf256::ONE).to_bool());
        assert!(Gf256(0x53).invert().ct_eq(&Gf256(0xca)).to_bool());
    }

    #[test]
    fn test_gf256_mul_exhaustive() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert!((Gf256(a) * Gf256(b))
                    .ct_eq(&Gf256(mul_reference(a, b)))
                    .to_bool());
            }
        }
    }

    #[test]
    fn test_gf256_invert_exhaustive() {
        assert!(Gf256::ZERO.invert().ct_eq(&Gf256::ZERO).to_bool());
        for a in 1..=255u8 {
            let x = Gf256(a);
            assert!((x * x.invert()).ct_eq(&Gf256::ONE).to_bool());
            assert!((x / x).ct_eq(&Gf256::ONE).to_bool());
        }
    }

    #[test]
    fn test_gf256_sqrt_exhaustive() {
        for a in 0..=255u8 {
            let x = Gf256(a);
            let (root, valid) = FieldElement::sqrt(x, Gf256::ONE);
            assert!(valid.to_bool());
            assert!(root.square().ct_eq(&x).to_bool());
            assert!(FieldElement::sqrt(x.square(), Gf256::ONE)
                .0
                .ct_eq(&x)
                .to_bool());
        }
        let (root, valid) = FieldElement::sqrt(Gf256(0x57), Gf256::ZERO);
        assert!(!valid.to_bool());
        assert!(root.ct_eq(&Gf256::ZERO).to_bool());
    }

    #[test]
    fn test_gf256_field_laws() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut bytes = [0u8; 3];
        for _ in 0..1000 {
            rng.fill(&mut bytes);
            let (a, b, c) = (Gf256(bytes[0]), Gf256(bytes[1]), Gf256(bytes[2]));
            assert!((a + b).ct_eq(&(b + a)).to_bool());
            assert!((a * b).ct_eq(&(b * a)).to_bool());
            assert!(((a + b) + c).ct_eq(&(a + (b + c))).to_bool());
            assert!(((a * b) * c).ct_eq(&(a * (b * c))).to_bool());
            assert!((a * (b + c)).ct_eq(&(a * b + a * c)).to_bool());
            assert!((a - b).ct_eq(&(a + b)).to_bool());
            assert!((-a).ct_eq(&a).to_bool());
            assert!((a + Gf256::ZERO).ct_eq(&a).to_bool());
            assert!((a * Gf256::ONE).ct_eq(&a).to_bool());
        }
    }
}
