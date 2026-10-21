use {
    crate::{
        traits::{ByteOrder, FieldElement},
        utils::Choice,
    },
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[derive(Clone, Copy)]
pub struct Gf256(u8);

impl Gf256 {
    const POLYNOMIAL: u8 = 0x1b;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }

    fn mul(self, rhs: Self) -> Self {
        let mut a = self.0;
        let mut b = rhs.0;
        let mut r = 0u8;
        for _ in 0..8 {
            r ^= a & Choice::nonzero(b & 1).mask::<u8>();
            a = (a << 1) ^ (Self::POLYNOMIAL & Choice::nonzero(a >> 7).mask::<u8>());
            b >>= 1;
        }
        Self(r)
    }

    fn square(self) -> Self {
        self.mul(self)
    }

    fn invert(self) -> Self {
        let x = self;
        let x4 = x.square().square();
        let x8 = x4.square();
        let x9 = x8.mul(x);
        let x25 = x8.square().mul(x9);
        let x50 = x25.square();
        let x250 = x50.square().square().mul(x50);
        x250.mul(x4)
    }

    fn sqrt(self) -> Self {
        let mut x = self;
        for _ in 0..7 {
            x = x.square();
        }
        x
    }

    fn swap(a: &mut Self, b: &mut Self, condition: Choice) {
        let swapped = *a;
        *a = Self::select(a, b, condition);
        *b = Self::select(b, &swapped, condition);
    }

    fn select(a: &Self, b: &Self, condition: Choice) -> Self {
        Self(condition.select(a.0, b.0))
    }

    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::eq(self.0, other.0)
    }
}

impl Add for Gf256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl AddAssign for Gf256 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Sub for Gf256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl SubAssign for Gf256 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl Neg for Gf256 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self
    }
}

impl Mul for Gf256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl MulAssign for Gf256 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl From<[u8; 1]> for Gf256 {
    fn from(value: [u8; 1]) -> Self {
        Self(value[0])
    }
}

impl From<Gf256> for [u8; 1] {
    fn from(value: Gf256) -> Self {
        [value.0]
    }
}

impl FieldElement for Gf256 {
    const ZERO: Self = Self(0);
    const ONE: Self = Self(1);

    const CAPACITY: usize = 8;
    const BYTE_ORDER: ByteOrder = ByteOrder::LittleEndian;

    type Bytes = [u8; 1];

    fn swap(a: &mut Self, b: &mut Self, condition: Choice) {
        Self::swap(a, b, condition);
    }

    fn select(a: &Self, b: &Self, condition: Choice) -> Self {
        Self::select(a, b, condition)
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
        let valid = !b.ct_eq(&Self::ZERO);
        let r = self.mul(b.invert()).sqrt();
        (Self::select(&Self::ZERO, &r, valid), valid)
    }

    fn from_u32(value: u32) -> Self {
        Self(value as u8)
    }
}
