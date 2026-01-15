use {
    crate::traits::FieldElement,
    core::{
        cmp::PartialEq,
        ops::{Add, Index, IndexMut, Mul, Neg, Sub},
    },
};

#[derive(Clone, Copy)]
pub struct Curve25519([u64; 5]);

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

impl Add for Curve25519 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut result = Self([
            self[0] + rhs[0],
            self[1] + rhs[1],
            self[2] + rhs[2],
            self[3] + rhs[3],
            self[4] + rhs[4],
        ]);
        result.reduce();
        result
    }
}

impl Mul for Curve25519 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let r1_19 = rhs[1] * 19;
        let r2_19 = rhs[2] * 19;
        let r3_19 = rhs[3] * 19;
        let r4_19 = rhs[4] * 19;
        let mut t = [0u128; 5];
        t[0] = m(self[0], rhs[0])
            + m(self[4], r1_19)
            + m(self[3], r2_19)
            + m(self[2], r3_19)
            + m(self[1], r4_19);
        t[1] = m(self[1], rhs[0])
            + m(self[0], rhs[1])
            + m(self[4], r2_19)
            + m(self[3], r3_19)
            + m(self[2], r4_19);
        t[2] = m(self[2], rhs[0])
            + m(self[1], rhs[1])
            + m(self[0], rhs[2])
            + m(self[4], r3_19)
            + m(self[3], r4_19);
        t[3] = m(self[3], rhs[0])
            + m(self[2], rhs[1])
            + m(self[1], rhs[2])
            + m(self[0], rhs[3])
            + m(self[4], r4_19);
        t[4] = m(self[4], rhs[0])
            + m(self[3], rhs[1])
            + m(self[2], rhs[2])
            + m(self[1], rhs[3])
            + m(self[0], rhs[4]);
        Self::new(t)
    }
}

impl Neg for Curve25519 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut result = Self([
            Self::P[0] - self[0],
            Self::P[1] - self[1],
            Self::P[2] - self[2],
            Self::P[3] - self[3],
            Self::P[4] - self[4],
        ]);
        result.reduce();
        result
    }
}

impl Sub for Curve25519 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut result = Self([
            Self::P[0] + self[0] - rhs[0],
            Self::P[1] + self[1] - rhs[1],
            Self::P[2] + self[2] - rhs[2],
            Self::P[3] + self[3] - rhs[3],
            Self::P[4] + self[4] - rhs[4],
        ]);
        result.reduce();
        result
    }
}

impl From<&[u8; 32]> for Curve25519 {
    fn from(value: &[u8; 32]) -> Self {
        let mut words = [0u64; 4];
        let (chunks, _) = value.as_chunks::<8>();
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u64::from_le_bytes(*chunk);
        }
        let mut r = Self::ZERO;
        r[0] = words[0];
        r[1] = (words[0] >> 51) | (words[1] << 13);
        r[2] = (words[1] >> 38) | (words[2] << 26);
        r[3] = (words[2] >> 25) | (words[3] << 39);
        r[4] = words[3] >> 12;
        r.mask();
        r
    }
}

impl From<Curve25519> for [u8; 32] {
    fn from(mut value: Curve25519) -> Self {
        value.canonical();
        let words = [
            value[0] | (value[1] << 51),
            value[1] >> 13 | (value[2] << 38),
            value[2] >> 26 | (value[3] << 25),
            value[3] >> 39 | (value[4] << 12),
        ];
        let mut bytes = [0u8; 32];
        let (chunks, _) = bytes.as_chunks_mut::<8>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&words[i].to_le_bytes());
        }
        bytes
    }
}

impl Curve25519 {
    pub(super) const ONE: Self = Self([1, 0, 0, 0, 0]);
    pub(super) const ZERO: Self = Self([0; 5]);
    pub(super) const SQRT_M1: Self = Self([
        1718705420411056,
        234908883556509,
        2233514472574048,
        2117202627021982,
        765476049583133,
    ]);
    const MASK: u64 = (1u64 << 51) - 1;
    const P: Self = Self([
        4503599627370458,
        4503599627370494,
        4503599627370494,
        4503599627370494,
        4503599627370494,
    ]);

    pub(crate) const fn from_51bit(value: [u64; 5]) -> Self {
        Self(value)
    }

    pub(super) fn swap(a: &mut Self, b: &mut Self, condition: u64) {
        let mask = ((condition != 0) as u64).wrapping_neg();
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    pub(super) fn square(self) -> Self {
        let a = &self;
        let a3_19 = a[3] * 19;
        let a4_19 = a[4] * 19;
        let a0_2 = a[0] * 2;
        let a1_2 = a[1] * 2;
        let a2_2 = a[2] * 2;
        let a3_38 = a3_19 * 2;
        let mut t = [0u128; 5];
        t[0] = m(a[0], a[0]) + m(a1_2, a4_19) + m(a2_2, a3_19);
        t[1] = m(a[3], a3_19) + m(a0_2, a[1]) + m(a2_2, a4_19);
        t[2] = m(a[1], a[1]) + m(a0_2, a[2]) + m(a[4], a3_38);
        t[3] = m(a[4], a4_19) + m(a0_2, a[3]) + m(a1_2, a[2]);
        t[4] = m(a[2], a[2]) + m(a0_2, a[4]) + m(a1_2, a[3]);
        Self::new(t)
    }

    fn new(mut words: [u128; 5]) -> Self {
        words[1] += ((words[0] >> 51) as u64) as u128;
        words[2] += ((words[1] >> 51) as u64) as u128;
        words[3] += ((words[2] >> 51) as u64) as u128;
        words[4] += ((words[3] >> 51) as u64) as u128;
        let carry = (words[4] >> 51) as u64;
        let mut t = [
            (words[0] as u64) & Self::MASK,
            (words[1] as u64) & Self::MASK,
            (words[2] as u64) & Self::MASK,
            (words[3] as u64) & Self::MASK,
            (words[4] as u64) & Self::MASK,
        ];
        t[0] += carry * 19;
        t[1] += t[0] >> 51;
        t[2] += t[1] >> 51;
        t[0] &= Self::MASK;
        t[1] &= Self::MASK;
        Self(t)
    }

    fn reduce(&mut self) {
        self.carry();
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
