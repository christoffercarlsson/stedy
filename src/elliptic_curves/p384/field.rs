use {
    super::P384,
    crate::{
        traits::{ByteOrder, FieldElement, MontgomeryParams, WeierstrassParams},
        utils::Choice,
    },
    core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[cfg_attr(target_pointer_width = "32", path = "field32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field64.rs")]
mod field_p384;

pub use field_p384::FieldP384;

#[derive(Clone, Copy)]
pub struct FieldP384Params;

impl MontgomeryParams<6> for FieldP384Params {
    const MOD: [u64; 6] = [
        4294967295,
        18446744069414584320,
        18446744073709551614,
        18446744073709551615,
        18446744073709551615,
        18446744073709551615,
    ];
    const ONE: [u64; 6] = [18446744069414584321, 4294967295, 1, 0, 0, 0];
    const R2: [u64; 6] = [
        18446744065119617025,
        8589934592,
        18446744065119617024,
        8589934592,
        1,
        0,
    ];
    const N0: u64 = 4294967297;
}

impl FieldP384 {
    const fn table_from_bytes(table: &[[[u8; 48]; 2]; 8]) -> [[Self; 2]; 8] {
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
        let f128 = f64 * f64.pow2n(64);
        let f24 = f8 * f16.pow2n(8);
        let f28 = f4 * f24.pow2n(4);
        let f30 = f2 * f28.pow2n(2);
        let f192 = f64 * f128.pow2n(64);
        let f224 = f32 * f192.pow2n(32);
        let f240 = f16 * f224.pow2n(16);
        let f248 = f8 * f240.pow2n(8);
        let f252 = f4 * f248.pow2n(4);
        let f254 = f2 * f252.pow2n(2);
        let f255 = x * f254.pow2n(1);
        let acc = f32 * f255.pow2n(33);
        f30 * acc.pow2n(94)
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

impl Add for FieldP384 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl AddAssign for FieldP384 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Sub for FieldP384 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(rhs)
    }
}

impl SubAssign for FieldP384 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl Neg for FieldP384 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl Mul for FieldP384 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl MulAssign for FieldP384 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl Div for FieldP384 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.mul(rhs.invert())
    }
}

impl DivAssign for FieldP384 {
    fn div_assign(&mut self, rhs: Self) {
        *self = self.div(rhs);
    }
}

impl From<&[u8; 48]> for FieldP384 {
    fn from(value: &[u8; 48]) -> Self {
        Self::from_be_bytes(value)
    }
}

impl From<[u8; 48]> for FieldP384 {
    fn from(value: [u8; 48]) -> Self {
        Self::from(&value)
    }
}

impl From<u32> for FieldP384 {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<FieldP384> for [u8; 48] {
    fn from(value: FieldP384) -> Self {
        value.to_be_bytes()
    }
}

impl From<&FieldP384> for [u8; 48] {
    fn from(value: &FieldP384) -> Self {
        Self::from(*value)
    }
}

impl FieldElement for FieldP384 {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    const CAPACITY: usize = 383;
    const BYTE_ORDER: ByteOrder = ByteOrder::BigEndian;

    type Bytes = [u8; 48];

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
}

impl WeierstrassParams<FieldP384> for FieldP384 {
    const A: FieldP384 = FieldP384::from_be_bytes_const(&P384::A);
    const B: FieldP384 = FieldP384::from_be_bytes_const(&P384::B);
    const BASE_POINT_X: FieldP384 = FieldP384::from_be_bytes_const(&P384::BASE_POINT_X);
    const BASE_POINT_Y: FieldP384 = FieldP384::from_be_bytes_const(&P384::BASE_POINT_Y);
    const BASE_NAF: [[FieldP384; 2]; 8] = FieldP384::table_from_bytes(&P384::BASE_NAF);
    const BASE_COMB_LOW: [[FieldP384; 2]; 8] = FieldP384::table_from_bytes(&P384::BASE_COMB_LOW);
    const BASE_COMB_HIGH: [[FieldP384; 2]; 8] = FieldP384::table_from_bytes(&P384::BASE_COMB_HIGH);

    type PointBytes = [u8; 49];
}
