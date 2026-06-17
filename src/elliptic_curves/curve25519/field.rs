use {
    crate::traits::{EdwardsParams, FieldElement},
    core::{
        cmp::PartialEq,
        ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    },
};

#[cfg_attr(target_pointer_width = "32", path = "field32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field64.rs")]
mod field25519;

pub use field25519::Field25519;

impl Field25519 {
    const SQRT_M1: Self = Self::from_limbs([
        1718705420411056,
        234908883556509,
        2233514472574048,
        2117202627021982,
        765476049583133,
    ]);

    fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        let size = slice.len().min(32);
        bytes[..size].copy_from_slice(&slice[..size]);
        Self::from(&bytes)
    }

    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        let mut x = *a;
        let mut y = *b;
        Self::swap(&mut x, &mut y, condition);
        x
    }

    fn invert(self) -> Self {
        let x = self;
        let x3 = x * x.square();
        x3 * x.pow22523().pow2n(3)
    }

    fn pow22523(self) -> Self {
        let x = self;
        let x2 = x.square();
        let x4 = x2.square();
        let x8 = x4.square();
        let x9 = x * x8;
        let x11 = x2 * x9;
        let x22 = x11.square();
        let x31 = x9 * x22;
        let x10 = x31 * x31.pow2n(5);
        let x20 = x10 * x10.pow2n(10);
        let x40 = x20 * x20.pow2n(20);
        let x50 = x10 * x40.pow2n(10);
        let x100 = x50 * x50.pow2n(50);
        let x200 = x100 * x100.pow2n(100);
        let x250 = x50 * x200.pow2n(50);
        x * x250.pow2n(2)
    }

    fn pow2n(self, n: usize) -> Self {
        let mut x = self.square();
        for _ in 1..n {
            x = x.square();
        }
        x
    }

    fn sqrt(self, b: Self) -> (Self, u64) {
        let a = self;
        let b3 = b * b.square();
        let b7 = b * b3.square();
        let u = a * b3 * (a * b7).pow22523();
        let v = u * Self::SQRT_M1;
        let c = b * u.square();
        let d = b * v.square();
        let e = (c == a) as u64;
        let f = (d == a) as u64;
        let valid = e | f;
        let r = Self::select(&v, &u, e);
        let r = Self::select(&Self::ZERO, &r, valid);
        (r, valid)
    }
}

impl Add for Field25519 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl AddAssign for Field25519 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Sub for Field25519 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(rhs)
    }
}

impl SubAssign for Field25519 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl Neg for Field25519 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl Mul for Field25519 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl MulAssign for Field25519 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl Div for Field25519 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.mul(rhs.invert())
    }
}

impl DivAssign for Field25519 {
    fn div_assign(&mut self, rhs: Self) {
        *self = self.div(rhs);
    }
}

impl PartialEq for Field25519 {
    fn eq(&self, other: &Self) -> bool {
        self.eq(other)
    }
}

impl Eq for Field25519 {}

impl From<&[u8; 32]> for Field25519 {
    fn from(value: &[u8; 32]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<[u8; 32]> for Field25519 {
    fn from(value: [u8; 32]) -> Self {
        Self::from(&value)
    }
}

impl From<&[u8]> for Field25519 {
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}

impl From<u32> for Field25519 {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<Field25519> for [u8; 32] {
    fn from(value: Field25519) -> Self {
        value.to_bytes()
    }
}

impl From<&Field25519> for [u8; 32] {
    fn from(value: &Field25519) -> Self {
        Self::from(*value)
    }
}

impl FieldElement for Field25519 {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

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

impl EdwardsParams<Field25519> for Field25519 {
    const D: Self = Self::from_limbs([
        929955233495203,
        466365720129213,
        1662059464998953,
        2033849074728123,
        1442794654840575,
    ]);
    const D2: Self = Self::from_limbs([
        1859910466990425,
        932731440258426,
        1072319116312658,
        1815898335770999,
        633789495995903,
    ]);
    const BASE_POINT_X: Self = Self::from_limbs([
        1738742601995546,
        1146398526822698,
        2070867633025821,
        562264141797630,
        587772402128613,
    ]);
    const BASE_POINT_Y: Self = Self::from_limbs([
        1801439850948184,
        1351079888211148,
        450359962737049,
        900719925474099,
        1801439850948198,
    ]);
    const BASE_POINT_T: Self = Self::from_limbs([
        1841354044333475,
        16398895984059,
        755974180946558,
        900171276175154,
        1821297809914039,
    ]);
}
