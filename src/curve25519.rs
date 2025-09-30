use core::{
    cmp::{Eq, PartialEq},
    ops::{Add, AddAssign, Div, Index, IndexMut, Mul, MulAssign, Neg, Sub},
};

#[derive(Clone, Copy)]
pub struct Curve25519(pub [u64; 5]);

impl Curve25519 {
    const MASK: u64 = (1u64 << 51) - 1;
    const P: Self = Self([
        4503599627370458,
        4503599627370494,
        4503599627370494,
        4503599627370494,
        4503599627370494,
    ]);
    const SQRT_M1: Self = Self([
        1718705420411056,
        234908883556509,
        2233514472574048,
        2117202627021982,
        765476049583133,
    ]);

    pub const ONE: Self = Self([1, 0, 0, 0, 0]);
    pub const ZERO: Self = Self([0; 5]);

    pub fn select(a: &Self, b: &Self, condition: u64) -> Self {
        let mut x = *a;
        let mut y = *b;
        Self::swap(&mut x, &mut y, condition);
        x
    }

    pub fn swap(a: &mut Self, b: &mut Self, condition: u64) {
        let mask = ((condition != 0) as u64).wrapping_neg();
        let x = a.0;
        let y = b.0;
        a.0 = [
            x[0] & !mask | y[0] & mask,
            x[1] & !mask | y[1] & mask,
            x[2] & !mask | y[2] & mask,
            x[3] & !mask | y[3] & mask,
            x[4] & !mask | y[4] & mask,
        ];
        b.0 = [
            y[0] & !mask | x[0] & mask,
            y[1] & !mask | x[1] & mask,
            y[2] & !mask | x[2] & mask,
            y[3] & !mask | x[3] & mask,
            y[4] & !mask | x[4] & mask,
        ];
    }

    pub fn add(self, rhs: Self) -> Self {
        Self::from([
            self[0] + rhs[0],
            self[1] + rhs[1],
            self[2] + rhs[2],
            self[3] + rhs[3],
            self[4] + rhs[4],
        ])
    }

    pub fn sub(self, rhs: Self) -> Self {
        Self::from([
            Self::P[0] + self[0] - rhs[0],
            Self::P[1] + self[1] - rhs[1],
            Self::P[2] + self[2] - rhs[2],
            Self::P[3] + self[3] - rhs[3],
            Self::P[4] + self[4] - rhs[4],
        ])
    }

    pub fn neg(self) -> Self {
        Self::from([
            Self::P[0] - self[0],
            Self::P[1] - self[1],
            Self::P[2] - self[2],
            Self::P[3] - self[3],
            Self::P[4] - self[4],
        ])
    }

    pub fn mul(self, rhs: Self) -> Self {
        let mut t = [0u128; 5];
        t[0] += m(self[0], rhs[0]);
        t[0] += m(self[4], rhs[1] * 19);
        t[0] += m(self[3], rhs[2] * 19);
        t[0] += m(self[2], rhs[3] * 19);
        t[0] += m(self[1], rhs[4] * 19);
        t[1] += m(self[1], rhs[0]);
        t[1] += m(self[0], rhs[1]);
        t[1] += m(self[4], rhs[2] * 19);
        t[1] += m(self[3], rhs[3] * 19);
        t[1] += m(self[2], rhs[4] * 19);
        t[2] += m(self[2], rhs[0]);
        t[2] += m(self[1], rhs[1]);
        t[2] += m(self[0], rhs[2]);
        t[2] += m(self[4], rhs[3] * 19);
        t[2] += m(self[3], rhs[4] * 19);
        t[3] += m(self[3], rhs[0]);
        t[3] += m(self[2], rhs[1]);
        t[3] += m(self[1], rhs[2]);
        t[3] += m(self[0], rhs[3]);
        t[3] += m(self[4], rhs[4] * 19);
        t[4] += m(self[4], rhs[0]);
        t[4] += m(self[3], rhs[1]);
        t[4] += m(self[2], rhs[2]);
        t[4] += m(self[1], rhs[3]);
        t[4] += m(self[0], rhs[4]);
        Self::from(t)
    }

    pub fn square(self) -> Self {
        let a = &self;
        let mut t = [0u128; 5];
        t[0] = m(a[0], a[0]);
        t[0] += 2 * (m(a[1], a[4] * 19) + m(a[2], a[3] * 19));
        t[1] = m(a[3], a[3] * 19);
        t[1] += 2 * (m(a[0], a[1]) + m(a[2], a[4] * 19));
        t[2] += m(a[1], a[1]);
        t[2] += 2 * (m(a[0], a[2]) + m(a[4], a[3] * 19));
        t[3] = m(a[4], a[4] * 19);
        t[3] += 2 * (m(a[0], a[3]) + m(a[1], a[2]));
        t[4] = m(a[2], a[2]);
        t[4] += 2 * (m(a[0], a[4]) + m(a[1], a[3]));
        Self::from(t)
    }

    pub fn div(self, rhs: Self) -> Self {
        self.mul(rhs.invert())
    }

    pub fn sqrt(self, b: Self) -> (Self, u64) {
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

    pub fn invert(self) -> Self {
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

    fn reduce(&mut self) {
        let carry = self[4] >> 51;
        self.mask();
        self[0] += carry * 19;
        self[1] += self[0] >> 51;
        self[2] += self[1] >> 51;
        self[0] &= Self::MASK;
        self[1] &= Self::MASK;
    }

    fn carry(&mut self) {
        self[1] += self[0] >> 51;
        self[2] += self[1] >> 51;
        self[3] += self[2] >> 51;
        self[4] += self[3] >> 51;
    }

    fn mask(&mut self) {
        self[0] &= Self::MASK;
        self[1] &= Self::MASK;
        self[2] &= Self::MASK;
        self[3] &= Self::MASK;
        self[4] &= Self::MASK;
    }

    fn canonical(&mut self) {
        let mut reduced = self.clone();
        reduced[0] += 19;
        reduced.carry();
        reduced[4] = reduced[4].wrapping_sub(1 << 51);
        let borrow = reduced[4] >> 63;
        reduced.mask();
        *self = Self::select(&reduced, &self, borrow);
    }
}

fn m(x: u64, y: u64) -> u128 {
    (x as u128) * (y as u128)
}

impl Index<usize> for Curve25519 {
    type Output = u64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Curve25519 {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl PartialEq for Curve25519 {
    fn eq(&self, other: &Self) -> bool {
        let mut diff = self.sub(*other);
        diff.canonical();
        let result = diff[0] | diff[1] | diff[2] | diff[3] | diff[4];
        result == 0
    }
}

impl Eq for Curve25519 {}

impl Add for Curve25519 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl AddAssign for Curve25519 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Div for Curve25519 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.div(rhs)
    }
}

impl Mul for Curve25519 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl MulAssign for Curve25519 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl Neg for Curve25519 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl Sub for Curve25519 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(rhs)
    }
}

impl From<[u128; 5]> for Curve25519 {
    fn from(mut value: [u128; 5]) -> Self {
        value[1] += ((value[0] >> 51) as u64) as u128;
        value[2] += ((value[1] >> 51) as u64) as u128;
        value[3] += ((value[2] >> 51) as u64) as u128;
        value[4] += ((value[3] >> 51) as u64) as u128;
        let carry = (value[4] >> 51) as u64;
        let mut t = [
            (value[0] as u64) & Self::MASK,
            (value[1] as u64) & Self::MASK,
            (value[2] as u64) & Self::MASK,
            (value[3] as u64) & Self::MASK,
            (value[4] as u64) & Self::MASK,
        ];
        t[0] += carry * 19;
        t[1] += t[0] >> 51;
        t[2] += t[1] >> 51;
        t[0] &= Self::MASK;
        t[1] &= Self::MASK;
        Self(t)
    }
}

impl From<[u64; 5]> for Curve25519 {
    fn from(value: [u64; 5]) -> Self {
        let mut result = Self(value);
        result.carry();
        result.reduce();
        result
    }
}

impl From<u64> for Curve25519 {
    fn from(value: u64) -> Self {
        Self::from([value, 0, 0, 0, 0])
    }
}

impl From<u32> for Curve25519 {
    fn from(value: u32) -> Self {
        Self::from(value as u64)
    }
}

impl From<[u64; 4]> for Curve25519 {
    fn from(value: [u64; 4]) -> Self {
        let mut r = Self::ZERO;
        r[0] = value[0];
        r[1] = (value[0] >> 51) | (value[1] << 13);
        r[2] = (value[1] >> 38) | (value[2] << 26);
        r[3] = (value[2] >> 25) | (value[3] << 39);
        r[4] = value[3] >> 12;
        r.mask();
        r
    }
}

impl From<&[u8]> for Curve25519 {
    fn from(value: &[u8]) -> Self {
        Self::from([
            u64::from_le_bytes(value[0..8].try_into().unwrap()),
            u64::from_le_bytes(value[8..16].try_into().unwrap()),
            u64::from_le_bytes(value[16..24].try_into().unwrap()),
            u64::from_le_bytes(value[24..32].try_into().unwrap()),
        ])
    }
}

impl From<&[u8; 32]> for Curve25519 {
    fn from(value: &[u8; 32]) -> Self {
        Self::from(value.as_slice())
    }
}

impl From<Curve25519> for [u64; 4] {
    fn from(mut value: Curve25519) -> Self {
        value.canonical();
        [
            value[0] | (value[1] << 51),
            value[1] >> 13 | (value[2] << 38),
            value[2] >> 26 | (value[3] << 25),
            value[3] >> 39 | (value[4] << 12),
        ]
    }
}

impl From<Curve25519> for [u8; 32] {
    fn from(value: Curve25519) -> Self {
        let r: [u64; 4] = value.into();
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&r[0].to_le_bytes());
        bytes[8..16].copy_from_slice(&r[1].to_le_bytes());
        bytes[16..24].copy_from_slice(&r[2].to_le_bytes());
        bytes[24..32].copy_from_slice(&r[3].to_le_bytes());
        bytes
    }
}
