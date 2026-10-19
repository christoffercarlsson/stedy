use {
    super::Edwards25519,
    crate::{
        traits::{ByteOrder, EdwardsParams, FieldElement},
        utils::Choice,
    },
    core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
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

    const fn from_bytes(bytes: &[u8; 32]) -> Self {
        const MASK: u64 = (1 << 51) - 1;
        let (chunks, _) = bytes.as_chunks::<8>();
        let mut words = [0u64; 4];
        let mut i = 0;
        while i < 4 {
            words[i] = u64::from_le_bytes(chunks[i]);
            i += 1;
        }
        Self::from_limbs([
            words[0] & MASK,
            ((words[0] >> 51) | (words[1] << 13)) & MASK,
            ((words[1] >> 38) | (words[2] << 26)) & MASK,
            ((words[2] >> 25) | (words[3] << 39)) & MASK,
            (words[3] >> 12) & MASK,
        ])
    }

    const fn table_from_bytes(table: &[[[u8; 32]; 3]; 8]) -> [[Self; 3]; 8] {
        let mut result = [[Self::ZERO; 3]; 8];
        let mut i = 0;
        while i < 8 {
            result[i] = [
                Self::from_bytes(&table[i][0]),
                Self::from_bytes(&table[i][1]),
                Self::from_bytes(&table[i][2]),
            ];
            i += 1;
        }
        result
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

    fn sqrt(self, b: Self) -> (Self, Choice) {
        let a = self;
        let b3 = b * b.square();
        let b7 = b * b3.square();
        let u = a * b3 * (a * b7).pow22523();
        let v = u * Self::SQRT_M1;
        let c = b * u.square();
        let d = b * v.square();
        let e = c.ct_eq(&a);
        let f = d.ct_eq(&a);
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

    const CAPACITY: usize = 254;
    const BYTE_ORDER: ByteOrder = ByteOrder::LittleEndian;

    type Bytes = [u8; 32];

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

    fn square2(self) -> Self {
        self.square2()
    }

    fn invert(self) -> Self {
        self.invert()
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        self.sqrt(b)
    }
}

impl EdwardsParams<Field25519> for Field25519 {
    const A: i8 = Edwards25519::A;
    const DOMAIN: &'static [u8] = Edwards25519::DOMAIN;
    const DOMAIN_PURE: bool = Edwards25519::DOMAIN_PURE;
    const D: Self = Self::from_bytes(&Edwards25519::D);
    const D2: Self = Self::from_bytes(&Edwards25519::D2);
    const BASE_POINT_X: Self = Self::from_bytes(&Edwards25519::BASE_POINT_X);
    const BASE_POINT_Y: Self = Self::from_bytes(&Edwards25519::BASE_POINT_Y);
    const BASE_POINT_T: Self = Self::from_bytes(&Edwards25519::BASE_POINT_T);
    const BASE_COMB_LOW: [[Self; 3]; 8] = Self::table_from_bytes(&Edwards25519::BASE_COMB_LOW);
    const BASE_COMB_HIGH: [[Self; 3]; 8] = Self::table_from_bytes(&Edwards25519::BASE_COMB_HIGH);
}
