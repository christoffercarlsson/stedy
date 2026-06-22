use {
    crate::traits::{FieldElement, WeierstrassParams},
    core::{
        cmp::PartialEq,
        ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    },
};

#[cfg_attr(target_pointer_width = "32", path = "field32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field64.rs")]
mod field_p384;

pub use field_p384::FieldP384;

impl FieldP384 {
    fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 48];
        let size = slice.len().min(48);
        bytes[..size].copy_from_slice(&slice[..size]);
        Self::from(&bytes)
    }

    fn invert(self) -> Self {
        let x = self;
        x * x.pow_p_minus_3_div_4().pow2n(2)
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

    fn sqrt(self, b: Self) -> (Self, u64) {
        let u = self;
        let v = b;
        let v2 = v.square();
        let v3 = v2 * v;
        let r = u * v * (u * v3).pow_p_minus_3_div_4();
        let c = v * r.square();
        let valid = (u == c) as u64;
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

impl PartialEq for FieldP384 {
    fn eq(&self, other: &Self) -> bool {
        self.eq(other)
    }
}

impl Eq for FieldP384 {}

impl From<&[u8; 48]> for FieldP384 {
    fn from(value: &[u8; 48]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<[u8; 48]> for FieldP384 {
    fn from(value: [u8; 48]) -> Self {
        Self::from(&value)
    }
}

impl From<&[u8]> for FieldP384 {
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}

impl From<u32> for FieldP384 {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<FieldP384> for [u8; 48] {
    fn from(value: FieldP384) -> Self {
        value.to_bytes()
    }
}

impl From<&FieldP384> for [u8; 48] {
    fn from(value: &FieldP384) -> Self {
        Self::from(*value)
    }
}

impl FieldElement for FieldP384 {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::R;

    type Bytes = [u8; 48];

    fn swap(a: &mut Self, b: &mut Self, condition: u64) {
        Self::swap(a, b, condition);
    }

    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        Self::select(a, b, condition)
    }

    fn square(self) -> Self {
        self.square()
    }

    fn invert(self) -> Self {
        self.invert()
    }

    fn sqrt(self, b: Self) -> (Self, u64) {
        self.sqrt(b)
    }
}

impl WeierstrassParams<FieldP384> for FieldP384 {
    const A: FieldP384 = FieldP384::from_limbs([
        3302829849855,
        71212069596168192,
        72057593987530751,
        72057594037927935,
        72057594037927935,
        72057594037927935,
        281474976710655,
    ]);
    const B: FieldP384 = FieldP384::from_limbs([
        38404636581678285,
        61158462543628305,
        7072068181174701,
        41529526856065179,
        9170902860951188,
        70287565570449154,
        8870372069311,
    ]);
    const BASE_POINT_X: FieldP384 = FieldP384::from_limbs([
        33044708514408525,
        63874851575184848,
        23673917422822264,
        45896911858449148,
        62535154744591449,
        5490067567239502,
        64517961260565,
    ]);
    const BASE_POINT_Y: FieldP384 = FieldP384::from_limbs([
        17360326591053355,
        53945015422690052,
        13092642221768616,
        68961204133816150,
        47359018512030056,
        65827211435194729,
        132679095424453,
    ]);

    type PointBytes = [u8; 49];
}
