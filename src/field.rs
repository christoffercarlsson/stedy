use core::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Sub, SubAssign,
};

const MAX_LIMBS: usize = 10;

#[derive(Clone, Copy)]
pub struct FieldElement<const LIMBS: usize, const BITS: usize, const Z: u64> {
    state: [u64; LIMBS],
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> FieldElement<LIMBS, BITS, Z> {
    const MASK: u64 = (1u64 << BITS) - 1;
    const ZERO: [u64; LIMBS] = [0u64; LIMBS];
    const ONE: [u64; LIMBS] = {
        let mut state = Self::ZERO;
        state[0] = 1;
        state
    };
    const P: [u64; LIMBS] = {
        let mut state = Self::ZERO;
        let mut i = 0;
        while i < LIMBS {
            state[i] = Self::MASK;
            i += 1;
        }
        state[0] -= Z - 1;
        state
    };
    const INVERSE: [u64; LIMBS] = {
        let mut state = Self::P;
        state[0] -= 2;
        state
    };
    const BALANCES: [u64; LIMBS] = {
        let mut state = Self::ZERO;
        let mut i = 0;
        while i < LIMBS {
            state[i] = Self::P[i] * 2;
            i += 1;
        }
        state
    };

    pub fn select(a: &Self, b: &Self, condition: u64) -> Self {
        let mut x = *a;
        let mut y = *b;
        Self::swap(&mut x, &mut y, condition);
        x
    }

    pub fn swap(a: &mut Self, b: &mut Self, condition: u64) {
        let mask = ((condition != 0) as u64).wrapping_neg();
        for i in 0..LIMBS {
            let t = mask & (a.state[i] ^ b.state[i]);
            a.state[i] ^= t;
            b.state[i] ^= t;
        }
    }

    pub fn zero() -> Self {
        Self { state: Self::ZERO }
    }

    pub fn one() -> Self {
        Self { state: Self::ONE }
    }

    pub fn add(self, rhs: Self) -> Self {
        let mut result = Self::zero();
        for i in 0..LIMBS {
            result.state[i] = self.state[i] + rhs.state[i];
        }
        result.reduce();
        result
    }

    pub fn sub(self, rhs: Self) -> Self {
        let mut result = Self::zero();
        for i in 0..LIMBS {
            result.state[i] = Self::BALANCES[i] + self.state[i] - rhs.state[i];
        }
        result.reduce();
        result
    }

    pub fn neg(self) -> Self {
        let mut result = Self::zero();
        for i in 0..LIMBS {
            result.state[i] = Self::BALANCES[i] - self.state[i];
        }
        result.reduce();
        result
    }

    pub fn mul(self, rhs: Self) -> Self {
        let mut product = [0u128; MAX_LIMBS];
        for i in 0..LIMBS {
            for j in 0..LIMBS {
                product[i + j] += self.state[i] as u128 * rhs.state[j] as u128;
            }
        }
        for i in LIMBS..MAX_LIMBS {
            product[i - LIMBS] += product[i] * (Z as u128);
        }
        let mask = (1u128 << BITS) - 1;
        let mut carry = 0u128;
        for i in 0..LIMBS {
            product[i] += carry;
            carry = product[i] >> BITS;
            product[i] &= mask;
        }
        product[0] += carry * (Z as u128);
        for i in 0..2 {
            carry = product[i] >> BITS;
            product[i] &= mask;
            product[i + 1] += carry;
        }
        let mut result = Self::zero();
        for i in 0..LIMBS {
            result.state[i] = product[i] as u64;
        }
        result
    }

    pub fn square(self) -> Self {
        self.mul(self)
    }

    pub fn pow(self, exponent: Self) -> Self {
        let mut result = Self::one();
        let mut base = self;
        for i in 0..LIMBS {
            for offset in 0..BITS {
                let product = result.mul(base);
                let value = (exponent.state[i] >> offset) & 1;
                result = Self::select(&result, &product, value);
                base = base.square();
            }
        }
        result
    }

    pub fn bitand(self, rhs: Self) -> Self {
        let mut result = Self::zero();
        for i in 0..LIMBS {
            result.state[i] = self.state[i] & rhs.state[i];
        }
        result
    }

    pub fn bitor(self, rhs: Self) -> Self {
        let mut result = Self::zero();
        for i in 0..LIMBS {
            result.state[i] = self.state[i] | rhs.state[i];
        }
        result
    }

    pub fn bitxor(self, rhs: Self) -> Self {
        let mut result = Self::zero();
        for i in 0..LIMBS {
            result.state[i] = self.state[i] ^ rhs.state[i];
        }
        result
    }

    pub fn div(self, rhs: Self) -> Self {
        self.mul(rhs.invert())
    }

    #[inline(always)]
    fn invert(self) -> Self {
        let exponent = Self {
            state: Self::INVERSE,
        };
        self.pow(exponent)
    }

    #[inline(always)]
    fn reduce(&mut self) {
        let mut carry = 0u64;
        for i in 0..LIMBS {
            self.state[i] += carry;
            carry = self.state[i] >> BITS;
            self.state[i] &= Self::MASK;
        }
        self.state[0] += carry * Z;
        for i in 0..2 {
            carry = self.state[i] >> BITS;
            self.state[i] &= Self::MASK;
            self.state[i + 1] += carry;
        }
    }

    fn from_bytes<const N: usize>(bytes: &[u8; N]) -> Self {
        let mut result = Self::zero();
        let mut pos = 0usize;
        for i in 0..LIMBS {
            for offset in 0..BITS {
                let byte_index = pos / 8;
                let byte_offset = pos % 8;
                let bit = (bytes[byte_index] >> byte_offset) & 1;
                result.state[i] |= (bit as u64) << offset;
                pos += 1;
            }
        }
        result.reduce();
        result
    }

    fn into_bytes<const N: usize>(self) -> [u8; N] {
        let result = self.canonical();
        let mut bytes = [0u8; N];
        let mut pos = 0usize;
        for i in 0..LIMBS {
            for offset in 0..BITS {
                let byte_index = pos / 8;
                let byte_offset = pos % 8;
                let bit = (result.state[i] >> offset) & 1;
                bytes[byte_index] |= (bit as u8) << byte_offset;
                pos += 1;
            }
        }
        bytes
    }

    #[inline(always)]
    fn canonical(self) -> Self {
        let mut reduced = Self::zero();
        let mut borrow = 0u64;
        for i in 0..LIMBS {
            let (diff, b1) = self.state[i].overflowing_sub(Self::P[i]);
            let (diff, b2) = diff.overflowing_sub(borrow);
            reduced.state[i] = diff & Self::MASK;
            borrow = (b1 | b2) as u64;
        }
        Self::select(&reduced, &self, borrow)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> Add for FieldElement<LIMBS, BITS, Z> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> AddAssign
    for FieldElement<LIMBS, BITS, Z>
{
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> BitAnd for FieldElement<LIMBS, BITS, Z> {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.bitand(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> BitAndAssign
    for FieldElement<LIMBS, BITS, Z>
{
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> BitOr for FieldElement<LIMBS, BITS, Z> {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.bitor(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> BitOrAssign
    for FieldElement<LIMBS, BITS, Z>
{
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> BitXor for FieldElement<LIMBS, BITS, Z> {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.bitxor(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> BitXorAssign
    for FieldElement<LIMBS, BITS, Z>
{
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> Div for FieldElement<LIMBS, BITS, Z> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.div(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> DivAssign
    for FieldElement<LIMBS, BITS, Z>
{
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> Mul for FieldElement<LIMBS, BITS, Z> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> MulAssign
    for FieldElement<LIMBS, BITS, Z>
{
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> Neg for FieldElement<LIMBS, BITS, Z> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> Sub for FieldElement<LIMBS, BITS, Z> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(rhs)
    }
}

impl<const LIMBS: usize, const BITS: usize, const Z: u64> SubAssign
    for FieldElement<LIMBS, BITS, Z>
{
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

pub type Curve25519 = FieldElement<5, 51, 19>;

impl From<&[u8; 32]> for Curve25519 {
    fn from(value: &[u8; 32]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<Curve25519> for [u8; 32] {
    fn from(value: Curve25519) -> Self {
        value.into_bytes::<32>()
    }
}

pub type Poly1305 = FieldElement<5, 26, 5>;

impl From<&[u8; 17]> for Poly1305 {
    fn from(value: &[u8; 17]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<&[u8; 16]> for Poly1305 {
    fn from(value: &[u8; 16]) -> Self {
        let mut bytes = [0u8; 17];
        bytes[..16].copy_from_slice(value);
        Self::from(&bytes)
    }
}

impl From<&[u8]> for Poly1305 {
    fn from(value: &[u8]) -> Self {
        let mut bytes = [0u8; 17];
        bytes[..16].copy_from_slice(value);
        Self::from(&bytes)
    }
}

impl From<Poly1305> for [u8; 16] {
    fn from(value: Poly1305) -> Self {
        let mut result = [0u8; 16];
        let bytes = value.into_bytes::<17>();
        result.copy_from_slice(&bytes[..16]);
        result
    }
}
