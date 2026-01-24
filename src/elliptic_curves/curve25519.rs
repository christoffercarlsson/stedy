#[cfg(target_pointer_width = "32")]
mod field32;
#[cfg(target_pointer_width = "64")]
mod field64;

use {
    crate::{
        elliptic_curves::Scalar25519,
        traits::{Curve, FieldElement, Scalar},
    },
    core::ops::{Add, AddAssign, Div, Mul, MulAssign},
};

#[cfg(target_pointer_width = "32")]
pub use field32::Curve25519;

#[cfg(target_pointer_width = "64")]
pub use field64::Curve25519;

impl Curve25519 {
    fn invert(self) -> Self {
        let a = self.pow22523();
        let b = a.pow2n(3);
        let c = self * self.square();
        b * c
    }

    fn pow22523(self) -> Self {
        let mut a = self.square();
        let mut b = a.square();
        b = self * b.square();
        a *= b;
        let mut c = a.square();
        b *= c;
        c = b.pow2n(5);
        b = c * b;
        c = b.pow2n(10);
        c *= b;
        let mut d = c.pow2n(20);
        c = d * c;
        c = c.pow2n(10);
        b = c * b;
        c = b.pow2n(50);
        c *= b;
        d = c.pow2n(100);
        c = d * c;
        c = c.pow2n(50);
        b = c * b;
        b = b.pow2n(2);
        self * b
    }

    fn pow2n(self, n: usize) -> Self {
        let mut x = self.square();
        for _ in 1..n {
            x = x.square();
        }
        x
    }
}

impl Eq for Curve25519 {}

impl AddAssign for Curve25519 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Div for Curve25519 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.mul(rhs.invert())
    }
}

impl MulAssign for Curve25519 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl From<[u8; 32]> for Curve25519 {
    fn from(value: [u8; 32]) -> Self {
        Self::from(&value)
    }
}

impl From<&[u8]> for Curve25519 {
    fn from(value: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        let size = value.len().min(32);
        bytes[..size].copy_from_slice(&value[..size]);
        Self::from(&bytes)
    }
}

impl From<u32> for Curve25519 {
    fn from(value: u32) -> Self {
        Self::from([value as u64, 0, 0, 0, 0])
    }
}

impl From<[u64; 5]> for Curve25519 {
    fn from(value: [u64; 5]) -> Self {
        Self::from_51bit(value)
    }
}

impl From<&Curve25519> for [u8; 32] {
    fn from(value: &Curve25519) -> Self {
        Self::from(*value)
    }
}

impl FieldElement for Curve25519 {
    const ONE: Self = Self::ONE;
    const ZERO: Self = Self::ZERO;

    type Bytes = [u8; 32];

    fn swap(a: &mut Self, b: &mut Self, condition: u64) {
        Self::swap(a, b, condition);
    }

    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        let mut x = *a;
        let mut y = *b;
        Self::swap(&mut x, &mut y, condition);
        x
    }

    fn square(self) -> Self {
        self.square()
    }

    fn invert(self) -> Self {
        self.invert()
    }

    fn sqrt(self, b: Self) -> (Self, u64) {
        let a = self;
        let b3 = b.square() * b;
        let b7 = b3.square() * b;
        let u = a * b3 * (a * b7).pow22523();
        let v = u * Self::SQRT_M1;
        let c = b * u.square();
        let d = b * v.square();
        let e = (c == a) as u64;
        let f = (d == a) as u64;
        let mut r = Self::select(&v, &u, e);
        let valid = e | f;
        r = Self::select(&Self::ZERO, &r, valid);
        (r, valid)
    }
}

impl Curve for Curve25519 {
    type Point = Self;
    type Scalar = [u8; 32];
    type PointBytes = [u8; 32];
    type ScalarBytes = [u8; 32];

    fn base_point() -> Self::Point {
        Self::from(9)
    }

    fn point_from_bytes(bytes: &Self::PointBytes) -> Option<Self::Point> {
        Some(Self::from(bytes))
    }

    fn point_to_bytes(point: &Self::Point) -> Self::PointBytes {
        point.into()
    }

    fn scalar_from_bytes(bytes: &Self::ScalarBytes) -> Option<Self::Scalar> {
        Some(*bytes)
    }

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes {
        *scalar
    }

    fn scalar_mult(scalar: &Self::Scalar, point: &Self::Point) -> Option<Self::Point> {
        let mut scalar = *scalar;
        Scalar25519::clamp(&mut scalar);
        let x1 = *point;
        let mut x2 = Self::ONE;
        let mut z2 = Self::ZERO;
        let mut x3 = *point;
        let mut z3 = Self::ONE;
        let mut swap = 0u64;
        for i in (0..255).rev() {
            let byte_index = i / 8;
            let bit_index = i % 8;
            let bit = ((scalar[byte_index] >> bit_index) & 1) as u64;
            swap ^= bit;
            Self::swap(&mut x2, &mut x3, swap);
            Self::swap(&mut z2, &mut z3, swap);
            swap = bit;
            let a = x2 + z2;
            let aa = a.square();
            let b = x2 - z2;
            let bb = b.square();
            let e = aa - bb;
            let c = x3 + z3;
            let d = x3 - z3;
            let da = d * a;
            let cb = c * b;
            x3 = (da + cb).square();
            z3 = x1 * (da - cb).square();
            x2 = aa * bb;
            let a24 = Self::from(121665);
            z2 = e * (aa + a24 * e);
        }
        Self::swap(&mut x2, &mut x3, swap);
        Self::swap(&mut z2, &mut z3, swap);
        Some(x2 / z2)
    }
}
