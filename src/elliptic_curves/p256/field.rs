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

    #[cfg(target_pointer_width = "64")]
    fn invert(self) -> Self {
        let x = self;
        x * x.pow_p_minus_3_div_4().pow2n(2)
    }

    #[cfg(target_pointer_width = "32")]
    fn invert(self) -> Self {
        self.invert_binary()
    }

    fn pow_p_minus_3_div_4(self) -> Self {
        let x = self;
        let f2 = x * x.square();
        let f4 = f2 * f2.pow2n(2);
        let f8 = f4 * f4.pow2n(4);
        let f16 = f8 * f8.pow2n(8);
        let f32 = f16 * f16.pow2n(16);
        let f64 = f32 * f32.pow2n(32);
        let f24 = f8 * f16.pow2n(8);
        let f28 = f4 * f24.pow2n(4);
        let f30 = f2 * f28.pow2n(2);
        let f94 = f30 * f64.pow2n(30);
        let acc = x * f32.pow2n(32);
        let acc = acc.pow2n(96);
        f94 * acc.pow2n(94)
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        let u = self;
        let v = b;
        let v2 = v.square();
        let v3 = v2 * v;
        let r = u * v * (u * v3).pow_p_minus_3_div_4();
        let c = v * r.square();
        let valid = u.ct_eq(&c);
        let r = Self::select(&Self::ZERO, &r, valid);
        (r, valid)
    }
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

    fn invert(self) -> Self {
        self.invert()
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        self.sqrt(b)
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
