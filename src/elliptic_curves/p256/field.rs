use {
    super::P256,
    crate::{
        traits::{ByteOrder, FieldElement, MontgomeryFormParams, WeierstrassParams},
        utils::Choice,
    },
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[cfg_attr(target_pointer_width = "32", path = "field32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field64.rs")]
mod field_p256;

pub use field_p256::FieldP256;

#[derive(Clone, Copy)]
pub struct FieldP256Params;

impl MontgomeryFormParams<4> for FieldP256Params {
    const MOD: [u64; 4] = [18446744073709551615, 4294967295, 0, 18446744069414584321];
    const ONE: [u64; 4] = [1, 18446744069414584320, 18446744073709551615, 4294967294];
    const R2: [u64; 4] = [3, 18446744056529682431, 18446744073709551614, 21474836477];
    const N0: u64 = 1;
}

impl FieldP256 {
    const fn table_from_bytes(table: &[[[u8; 32]; 2]; 8]) -> [[Self; 2]; 8] {
        let mut result = [[Self::ZERO; 2]; 8];
        let mut i = 0;
        while i < 8 {
            result[i] = [
                Self::from_be_bytes_const(&table[i][0]),
                Self::from_be_bytes_const(&table[i][1]),
            ];
            i += 1;
        }
        result
    }
}

pub(super) fn pow_p_minus_3_div_4<F>(x: F) -> F
where
    F: FieldElement,
{
    let f2 = x * x.square();
    let f4 = f2 * pow2n(f2, 2);
    let f8 = f4 * pow2n(f4, 4);
    let f16 = f8 * pow2n(f8, 8);
    let f32 = f16 * pow2n(f16, 16);
    let f64 = f32 * pow2n(f32, 32);
    let f24 = f8 * pow2n(f16, 8);
    let f28 = f4 * pow2n(f24, 4);
    let f30 = f2 * pow2n(f28, 2);
    let f94 = f30 * pow2n(f64, 30);
    let acc = x * pow2n(f32, 32);
    let acc = pow2n(acc, 96);
    f94 * pow2n(acc, 94)
}

pub(super) fn pow2n<F>(x: F, n: usize) -> F
where
    F: FieldElement,
{
    let mut x = x.square();
    for _ in 1..n {
        x = x.square();
    }
    x
}

pub(super) fn sqrt<F>(u: F, v: F) -> (F, Choice)
where
    F: FieldElement,
{
    let v2 = v.square();
    let v3 = v2 * v;
    let r = u * v * pow_p_minus_3_div_4(u * v3);
    let c = v * r.square();
    let valid = u.ct_eq(&c);
    let r = F::select(&F::ZERO, &r, valid);
    (r, valid)
}

impl Add for FieldP256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl AddAssign for FieldP256 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Sub for FieldP256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(rhs)
    }
}

impl SubAssign for FieldP256 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl Neg for FieldP256 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl Mul for FieldP256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl MulAssign for FieldP256 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl From<&[u8; 32]> for FieldP256 {
    fn from(value: &[u8; 32]) -> Self {
        Self::from_be_bytes(value)
    }
}

impl From<[u8; 32]> for FieldP256 {
    fn from(value: [u8; 32]) -> Self {
        Self::from(&value)
    }
}

impl From<FieldP256> for [u8; 32] {
    fn from(value: FieldP256) -> Self {
        value.to_be_bytes()
    }
}

impl From<&FieldP256> for [u8; 32] {
    fn from(value: &FieldP256) -> Self {
        Self::from(*value)
    }
}

impl FieldElement for FieldP256 {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    const CAPACITY: usize = 255;
    const BYTE_ORDER: ByteOrder = ByteOrder::BigEndian;

    type Bytes = [u8; 32];

    fn swap(a: &mut Self, b: &mut Self, condition: Choice) {
        Self::swap(a, b, condition);
    }

    fn select(a: &Self, b: &Self, condition: Choice) -> Self {
        Self::select(a, b, condition)
    }

    fn assign(&mut self, other: &Self, condition: Choice) {
        self.assign(other, condition);
    }

    fn ct_eq(&self, other: &Self) -> Choice {
        self.ct_eq(other)
    }

    fn square(self) -> Self {
        self.square()
    }

    #[cfg(target_pointer_width = "64")]
    fn invert(self) -> Self {
        self * pow2n(pow_p_minus_3_div_4(self), 2)
    }

    #[cfg(target_pointer_width = "32")]
    fn invert(self) -> Self {
        self.invert_binary()
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        sqrt(self, b)
    }

    fn from_u32(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl WeierstrassParams<FieldP256> for FieldP256 {
    const A: FieldP256 = FieldP256::from_be_bytes_const(&P256::A);
    const B: FieldP256 = FieldP256::from_be_bytes_const(&P256::B);
    const BASE_POINT_X: FieldP256 = FieldP256::from_be_bytes_const(&P256::BASE_POINT_X);
    const BASE_POINT_Y: FieldP256 = FieldP256::from_be_bytes_const(&P256::BASE_POINT_Y);
    const BASE_NAF: [[FieldP256; 2]; 8] = FieldP256::table_from_bytes(&P256::BASE_NAF);
    const BASE_COMB_LOW: [[FieldP256; 2]; 8] = FieldP256::table_from_bytes(&P256::BASE_COMB_LOW);
    const BASE_COMB_HIGH: [[FieldP256; 2]; 8] = FieldP256::table_from_bytes(&P256::BASE_COMB_HIGH);

    type PointBytes = [u8; 33];
}
