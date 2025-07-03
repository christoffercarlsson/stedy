use core::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Sub, SubAssign,
};

const MAX_LIMBS: usize = 8;

#[derive(Copy, Clone)]
pub struct Field<const LIMBS: usize, const BITS: usize, const Z: u128> {
    limbs: [u128; LIMBS],
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> Field<LIMBS, BITS, Z> {
    const MASK: u128 = (1 << BITS) - 1;

    pub fn zero() -> Self {
        Self { limbs: [0; LIMBS] }
    }

    pub fn one() -> Self {
        Self::from(1)
    }

    pub fn select(a: &Self, b: &Self, condition: u128) -> Self {
        let mut x = *a;
        let mut y = *b;
        Self::swap(&mut x, &mut y, condition);
        x
    }

    pub fn swap(a: &mut Self, b: &mut Self, condition: u128) {
        let mask = ((condition != 0) as u128).wrapping_neg();
        for i in 0..LIMBS {
            let t = mask & (a.limbs[i] ^ b.limbs[i]);
            a.limbs[i] ^= t;
            b.limbs[i] ^= t;
        }
    }

    pub fn add(self, rhs: Self) -> Self {
        let mut result = Self::zero();
        for i in 0..LIMBS {
            result.limbs[i] = self.limbs[i] + rhs.limbs[i];
        }
        result.reduce();
        result
    }

    pub fn sub(self, rhs: Self) -> Self {
        self.add(rhs.neg())
    }

    pub fn neg(self) -> Self {
        let p = Self::p();
        let (mut result, _) = Self::subtract(&p, &self);
        result.reduce();
        result
    }

    pub fn mul(self, rhs: Self) -> Self {
        let mut t = [0u128; MAX_LIMBS * 2];
        for i in 0..LIMBS {
            for j in 0..LIMBS {
                t[i + j] += self.limbs[i] * rhs.limbs[j];
            }
        }
        for i in LIMBS..(LIMBS * 2) {
            t[i - LIMBS] += t[i] * Z;
        }
        let mut result = Self::zero();
        for i in 0..LIMBS {
            result.limbs[i] = t[i];
        }
        result.reduce();
        result
    }

    pub fn square(self) -> Self {
        self.mul(self)
    }

    pub fn cube(self) -> Self {
        self.mul(self.square())
    }

    pub fn pow(self, exponent: Self) -> Self {
        let mut result = Self::one();
        let mut base = self;
        for pos in Self::bits() {
            let product = result.mul(base);
            let value = (exponent.limbs[pos.limb_index] >> pos.limb_offset) & 1;
            result = Self::select(&result, &product, value);
            base = base.square();
        }
        result
    }

    pub fn invert(self) -> Self {
        let p = Self::p();
        let two = Self::from(2);
        let exponent = p.sub(two);
        self.pow(exponent)
    }

    pub fn div(self, rhs: Self) -> Self {
        self.mul(rhs.invert())
    }

    pub fn bitand(self, rhs: Self) -> Self {
        let mut result = Self::zero();
        for i in 0..LIMBS {
            result.limbs[i] = self.limbs[i] & rhs.limbs[i];
        }
        result
    }

    pub fn bitor(self, rhs: Self) -> Self {
        let mut result = Self::zero();
        for i in 0..LIMBS {
            result.limbs[i] = self.limbs[i] | rhs.limbs[i];
        }
        result
    }

    pub fn bitxor(self, rhs: Self) -> Self {
        let mut result = Self::zero();
        for i in 0..LIMBS {
            result.limbs[i] = self.limbs[i] ^ rhs.limbs[i];
        }
        result
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut result = Self::zero();
        for pos in Self::bits().take(bytes.len() * 8) {
            let byte = bytes[pos.byte_index];
            let bit = (byte >> pos.byte_offset) & 1;
            result.limbs[pos.limb_index] |= (bit as u128) << pos.limb_offset;
        }
        result.reduce();
        result
    }

    fn bits() -> impl Iterator<Item = BitPosition> {
        (0..(LIMBS * BITS)).map(|pos| {
            let byte_index = pos / 8;
            let byte_offset = pos % 8;
            let limb_index = pos / BITS;
            let limb_offset = pos % BITS;
            BitPosition {
                byte_index,
                byte_offset,
                limb_index,
                limb_offset,
            }
        })
    }

    fn p() -> Self {
        let mut result = Self::zero();
        for i in 0..LIMBS {
            result.limbs[i] = Self::MASK;
        }
        result.limbs[0] -= Z - 1;
        result
    }

    fn subtract(a: &Self, b: &Self) -> (Self, u128) {
        let mut result = Self::zero();
        let mut borrow = 0u128;
        for i in 0..LIMBS {
            let (diff, b1) = a.limbs[i].overflowing_sub(b.limbs[i]);
            let (diff, b2) = diff.overflowing_sub(borrow);
            result.limbs[i] = diff & Self::MASK;
            borrow = (b1 | b2) as u128;
        }
        (result, borrow)
    }

    fn into_bytes<const N: usize>(self) -> [u8; N] {
        let mut bytes = [0u8; N];
        for pos in Self::bits().take(N * 8) {
            let bit = (self.limbs[pos.limb_index] >> pos.limb_offset) & 1;
            bytes[pos.byte_index] |= (bit as u8) << pos.byte_offset;
        }
        bytes
    }

    fn reduce(&mut self) {
        self.limbs[0] += self.carry() * Z;
        self.limbs[0] += self.carry() * Z;
        self.carry();
        let p = Self::p();
        let (reduced, borrow) = Self::subtract(&self, &p);
        *self = Self::select(&reduced, &self, borrow)
    }

    fn carry(&mut self) -> u128 {
        let mut result = Self::zero();
        let mut carry = 0u128;
        for i in 0..LIMBS {
            let sum = self.limbs[i] + carry;
            result.limbs[i] = sum & Self::MASK;
            carry = sum >> BITS;
        }
        *self = result;
        carry
    }
}

struct BitPosition {
    byte_index: usize,
    byte_offset: usize,
    limb_index: usize,
    limb_offset: usize,
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> From<u128> for Field<LIMBS, BITS, Z> {
    fn from(value: u128) -> Self {
        let mut result = Self::zero();
        result.limbs[0] = value;
        result.reduce();
        result
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> From<u8> for Field<LIMBS, BITS, Z> {
    fn from(value: u8) -> Self {
        Self::from(value as u128)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> From<u16> for Field<LIMBS, BITS, Z> {
    fn from(value: u16) -> Self {
        Self::from(value as u128)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> From<u32> for Field<LIMBS, BITS, Z> {
    fn from(value: u32) -> Self {
        Self::from(value as u128)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> From<i32> for Field<LIMBS, BITS, Z> {
    fn from(value: i32) -> Self {
        Self::from(value as u128)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> From<u64> for Field<LIMBS, BITS, Z> {
    fn from(value: u64) -> Self {
        Self::from(value as u128)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> From<Field<LIMBS, BITS, Z>> for u8 {
    fn from(value: Field<LIMBS, BITS, Z>) -> Self {
        let bytes = value.into_bytes::<1>();
        bytes[0]
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> From<Field<LIMBS, BITS, Z>> for u16 {
    fn from(value: Field<LIMBS, BITS, Z>) -> Self {
        let bytes = value.into_bytes::<2>();
        u16::from_le_bytes(bytes)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> From<Field<LIMBS, BITS, Z>> for u32 {
    fn from(value: Field<LIMBS, BITS, Z>) -> Self {
        let bytes = value.into_bytes::<4>();
        u32::from_le_bytes(bytes)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> From<Field<LIMBS, BITS, Z>> for u64 {
    fn from(value: Field<LIMBS, BITS, Z>) -> Self {
        let bytes = value.into_bytes::<8>();
        u64::from_le_bytes(bytes)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> From<Field<LIMBS, BITS, Z>> for u128 {
    fn from(value: Field<LIMBS, BITS, Z>) -> Self {
        let bytes = value.into_bytes::<16>();
        u128::from_le_bytes(bytes)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> From<&[u8]> for Field<LIMBS, BITS, Z> {
    fn from(value: &[u8]) -> Self {
        Self::from_bytes(value)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> Add for Field<LIMBS, BITS, Z> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> Sub for Field<LIMBS, BITS, Z> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> Neg for Field<LIMBS, BITS, Z> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> Mul for Field<LIMBS, BITS, Z> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> Div for Field<LIMBS, BITS, Z> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.div(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> BitAnd for Field<LIMBS, BITS, Z> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.bitand(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> BitOr for Field<LIMBS, BITS, Z> {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.bitor(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> BitXor for Field<LIMBS, BITS, Z> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.bitxor(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> AddAssign for Field<LIMBS, BITS, Z> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> SubAssign for Field<LIMBS, BITS, Z> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> MulAssign for Field<LIMBS, BITS, Z> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> DivAssign for Field<LIMBS, BITS, Z> {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> BitAndAssign for Field<LIMBS, BITS, Z> {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> BitOrAssign for Field<LIMBS, BITS, Z> {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u128> BitXorAssign for Field<LIMBS, BITS, Z> {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

pub type Poly1305Field = Field<5, 26, 5>;
pub type Curve25519Field = Field<5, 51, 19>;

impl From<Poly1305Field> for [u8; 16] {
    fn from(value: Poly1305Field) -> [u8; 16] {
        value.into_bytes::<16>()
    }
}

impl From<[u8; 17]> for Poly1305Field {
    fn from(value: [u8; 17]) -> Self {
        Self::from(value.as_slice())
    }
}

impl From<Curve25519Field> for [u8; 32] {
    fn from(value: Curve25519Field) -> [u8; 32] {
        value.into_bytes::<32>()
    }
}

impl From<[u8; 32]> for Curve25519Field {
    fn from(value: [u8; 32]) -> Self {
        Self::from(value.as_slice())
    }
}

impl From<&[u8; 32]> for Curve25519Field {
    fn from(value: &[u8; 32]) -> Self {
        Self::from(value.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_into_bytes() {
        let bytes = [
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let field = Curve25519Field::from(bytes);
        let result: [u8; 32] = field.into();
        assert_eq!(result, bytes);
        let field = Curve25519Field::from(9);
        let result: [u8; 32] = field.into();
        assert_eq!(result, bytes);
    }

    #[test]
    fn test_add() {
        let x = Curve25519Field::from(9);
        let y = Curve25519Field::from(9);
        let z: u32 = (x + y).into();
        assert_eq!(z, 18);
    }

    #[test]
    fn test_sub() {
        let x = Curve25519Field::from(9);
        let y = Curve25519Field::from(3);
        let z: u32 = (x - y).into();
        assert_eq!(z, 6);
    }

    #[test]
    fn test_mul() {
        let x = Curve25519Field::from(9);
        let y = Curve25519Field::from(3);
        let z: u32 = (x * y).into();
        assert_eq!(z, 27);
    }

    #[test]
    fn test_div() {
        let x = Curve25519Field::from(9);
        let y = Curve25519Field::from(3);
        let z: u32 = (x / y).into();
        assert_eq!(z, 3);
    }

    #[test]
    fn test_bitand() {
        let x = Curve25519Field::from(0b1100u32);
        let y = Curve25519Field::from(0b1010u32);
        let z: u32 = (x & y).into();
        assert_eq!(z, 0b1000);
        let x = Curve25519Field::from(42);
        let y = Curve25519Field::zero();
        let z: u32 = (x & y).into();
        assert_eq!(z, 0);
    }

    #[test]
    fn test_bitor() {
        let x = Curve25519Field::from(0b1100u32);
        let y = Curve25519Field::from(0b1010u32);
        let z: u32 = (x | y).into();
        assert_eq!(z, 0b1110);
        let x = Curve25519Field::from(42);
        let y = Curve25519Field::zero();
        let z: u32 = (x | y).into();
        assert_eq!(z, 42);
    }

    #[test]
    fn test_bitxor() {
        let x = Curve25519Field::from(0b1100u32);
        let y = Curve25519Field::from(0b1010u32);
        let z: u32 = (x ^ y).into();
        assert_eq!(z, 0b0110);
        let x = Curve25519Field::from(42);
        let y = Curve25519Field::from(42);
        let z: u32 = (x ^ y).into();
        assert_eq!(z, 0);
    }

    #[test]
    fn test_square() {
        let x = Curve25519Field::from(9);
        let y: u32 = x.square().into();
        assert_eq!(y, 81);
    }

    #[test]
    fn test_cube() {
        let x = Curve25519Field::from(9);
        let y: u32 = x.cube().into();
        assert_eq!(y, 729);
    }

    #[test]
    fn test_mul_u64() {
        let x = Curve25519Field::from(2_000_000_000_000_000_000u64);
        let y = Curve25519Field::from(3_000_000_000_000_000_000u64);
        let z: u128 = x.mul(y).into();
        assert_eq!(z, 6_000_000_000_000_000_000_000_000_000_000_000_000u128);
    }

    #[test]
    fn test_reduce() {
        let field = Curve25519Field::from([255u8; 32]);
        let result: u32 = field.into();
        assert_eq!(result, 18);
        let field = Poly1305Field::from([255u8; 17]);
        let result: u32 = field.into();
        assert_eq!(result, 4);
    }

    #[test]
    fn test_mul_reduce() {
        let x = Curve25519Field::from([255u8; 32]);
        let y = Curve25519Field::from(2);
        let z: u32 = (x * y).into();
        assert_eq!(z, 36);
    }

    #[test]
    fn test_invert() {
        let x = Curve25519Field::from([255u8; 32]);
        let y = x.invert();
        let z: u32 = (x * y).into();
        assert_eq!(z, 1);
    }
}
