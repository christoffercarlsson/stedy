#[cfg(target_pointer_width = "32")]
mod field32;
#[cfg(target_pointer_width = "64")]
mod field64;

use {
    crate::traits::FieldElement,
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
        a = a * b;
        let mut c = a.square();
        b = b * c;
        c = b.pow2n(5);
        b = c * b;
        c = b.pow2n(10);
        c = c * b;
        let mut d = c.pow2n(20);
        c = d * c;
        c = c.pow2n(10);
        b = c * b;
        c = b.pow2n(50);
        c = c * b;
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
