use {
    crate::traits::{FieldElement, WeierstrassParams},
    core::{
        cmp::PartialEq,
        ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    },
};

#[cfg_attr(target_pointer_width = "32", path = "field32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field64.rs")]
mod field_p256;

pub use field_p256::FieldP256;

impl FieldP256 {
    fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        let size = slice.len().min(32);
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
        let f24 = f8 * f16.pow2n(8);
        let f28 = f4 * f24.pow2n(4);
        let f30 = f2 * f28.pow2n(2);
        let f94 = f30 * f64.pow2n(30);
        let acc = x * f32.pow2n(32);
        let acc = acc.pow2n(96);
        f94 * acc.pow2n(94)
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

impl Div for FieldP256 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.mul(rhs.invert())
    }
}

impl DivAssign for FieldP256 {
    fn div_assign(&mut self, rhs: Self) {
        *self = self.div(rhs);
    }
}

impl PartialEq for FieldP256 {
    fn eq(&self, other: &Self) -> bool {
        self.eq(other)
    }
}

impl Eq for FieldP256 {}

impl From<&[u8; 32]> for FieldP256 {
    fn from(value: &[u8; 32]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<[u8; 32]> for FieldP256 {
    fn from(value: [u8; 32]) -> Self {
        Self::from(&value)
    }
}

impl From<&[u8]> for FieldP256 {
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}

impl From<u32> for FieldP256 {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<FieldP256> for [u8; 32] {
    fn from(value: FieldP256) -> Self {
        value.to_bytes()
    }
}

impl From<&FieldP256> for [u8; 32] {
    fn from(value: &FieldP256) -> Self {
        Self::from(*value)
    }
}

impl FieldElement for FieldP256 {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::R;

    type Bytes = [u8; 32];

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

impl WeierstrassParams<FieldP256> for FieldP256 {
    const A: FieldP256 = FieldP256::from_limbs([
        4503599627370447,
        862017116176383,
        0,
        3367254360064,
        281474973499392,
    ]);
    const B: FieldP256 = FieldP256::from_limbs([
        3929803208777213,
        3562985424476316,
        583760861921372,
        2309067332692983,
        214406409308276,
    ]);
    const BASE_POINT_X: FieldP256 = FieldP256::from_limbs([
        859000078943169,
        3465582099921383,
        1726581271406943,
        1625533376047991,
        150658718847861,
    ]);
    const BASE_POINT_Y: FieldP256 = FieldP256::from_limbs([
        1466185490456744,
        1189782786727410,
        597251050482574,
        3805765832181981,
        95794707978373,
    ]);

    type PointBytes = [u8; 33];
}
