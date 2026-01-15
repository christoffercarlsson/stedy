use core::{
    cmp::PartialEq,
    ops::{Add, Index, IndexMut, Mul, Neg, Sub},
};

#[derive(Clone, Copy)]
pub struct Curve25519(pub [i32; 10]);

impl Index<usize> for Curve25519 {
    type Output = i32;

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
        let result = diff[0]
            | diff[1]
            | diff[2]
            | diff[3]
            | diff[4]
            | diff[5]
            | diff[6]
            | diff[7]
            | diff[8]
            | diff[9];
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
            self[5] + rhs[5],
            self[6] + rhs[6],
            self[7] + rhs[7],
            self[8] + rhs[8],
            self[9] + rhs[9],
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
        let r5_19 = rhs[5] * 19;
        let r6_19 = rhs[6] * 19;
        let r7_19 = rhs[7] * 19;
        let r8_19 = rhs[8] * 19;
        let r9_19 = rhs[9] * 19;
        let s1_2 = self[1] * 2;
        let s3_2 = self[3] * 2;
        let s5_2 = self[5] * 2;
        let s7_2 = self[7] * 2;
        let s9_2 = self[9] * 2;
        let mut t = [0i64; 10];
        t[0] = m(self[0], rhs[0])
            + m(s1_2, r9_19)
            + m(self[2], r8_19)
            + m(s3_2, r7_19)
            + m(self[4], r6_19)
            + m(s5_2, r5_19)
            + m(self[6], r4_19)
            + m(s7_2, r3_19)
            + m(self[8], r2_19)
            + m(s9_2, r1_19);
        t[1] = m(self[0], rhs[1])
            + m(self[1], rhs[0])
            + m(self[2], r9_19)
            + m(self[3], r8_19)
            + m(self[4], r7_19)
            + m(self[5], r6_19)
            + m(self[6], r5_19)
            + m(self[7], r4_19)
            + m(self[8], r3_19)
            + m(self[9], r2_19);
        t[2] = m(self[0], rhs[2])
            + m(s1_2, rhs[1])
            + m(self[2], rhs[0])
            + m(s3_2, r9_19)
            + m(self[4], r8_19)
            + m(s5_2, r7_19)
            + m(self[6], r6_19)
            + m(s7_2, r5_19)
            + m(self[8], r4_19)
            + m(s9_2, r3_19);
        t[3] = m(self[0], rhs[3])
            + m(self[1], rhs[2])
            + m(self[2], rhs[1])
            + m(self[3], rhs[0])
            + m(self[4], r9_19)
            + m(self[5], r8_19)
            + m(self[6], r7_19)
            + m(self[7], r6_19)
            + m(self[8], r5_19)
            + m(self[9], r4_19);
        t[4] = m(self[0], rhs[4])
            + m(s1_2, rhs[3])
            + m(self[2], rhs[2])
            + m(s3_2, rhs[1])
            + m(self[4], rhs[0])
            + m(s5_2, r9_19)
            + m(self[6], r8_19)
            + m(s7_2, r7_19)
            + m(self[8], r6_19)
            + m(s9_2, r5_19);
        t[5] = m(self[0], rhs[5])
            + m(self[1], rhs[4])
            + m(self[2], rhs[3])
            + m(self[3], rhs[2])
            + m(self[4], rhs[1])
            + m(self[5], rhs[0])
            + m(self[6], r9_19)
            + m(self[7], r8_19)
            + m(self[8], r7_19)
            + m(self[9], r6_19);
        t[6] = m(self[0], rhs[6])
            + m(s1_2, rhs[5])
            + m(self[2], rhs[4])
            + m(s3_2, rhs[3])
            + m(self[4], rhs[2])
            + m(s5_2, rhs[1])
            + m(self[6], rhs[0])
            + m(s7_2, r9_19)
            + m(self[8], r8_19)
            + m(s9_2, r7_19);
        t[7] = m(self[0], rhs[7])
            + m(self[1], rhs[6])
            + m(self[2], rhs[5])
            + m(self[3], rhs[4])
            + m(self[4], rhs[3])
            + m(self[5], rhs[2])
            + m(self[6], rhs[1])
            + m(self[7], rhs[0])
            + m(self[8], r9_19)
            + m(self[9], r8_19);
        t[8] = m(self[0], rhs[8])
            + m(s1_2, rhs[7])
            + m(self[2], rhs[6])
            + m(s3_2, rhs[5])
            + m(self[4], rhs[4])
            + m(s5_2, rhs[3])
            + m(self[6], rhs[2])
            + m(s7_2, rhs[1])
            + m(self[8], rhs[0])
            + m(s9_2, r9_19);
        t[9] = m(self[0], rhs[9])
            + m(self[1], rhs[8])
            + m(self[2], rhs[7])
            + m(self[3], rhs[6])
            + m(self[4], rhs[5])
            + m(self[5], rhs[4])
            + m(self[6], rhs[3])
            + m(self[7], rhs[2])
            + m(self[8], rhs[1])
            + m(self[9], rhs[0]);
        Self::new(t)
    }
}

impl Neg for Curve25519 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut result = Self([
            -self[0], -self[1], -self[2], -self[3], -self[4], -self[5], -self[6], -self[7],
            -self[8], -self[9],
        ]);
        result.reduce();
        result
    }
}

impl Sub for Curve25519 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut result = Self([
            self[0] - rhs[0],
            self[1] - rhs[1],
            self[2] - rhs[2],
            self[3] - rhs[3],
            self[4] - rhs[4],
            self[5] - rhs[5],
            self[6] - rhs[6],
            self[7] - rhs[7],
            self[8] - rhs[8],
            self[9] - rhs[9],
        ]);
        result.reduce();
        result
    }
}

impl From<&[u8; 32]> for Curve25519 {
    fn from(value: &[u8; 32]) -> Self {
        let mut words = [0u32; 8];
        let (chunks, _) = value.as_chunks::<4>();
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u32::from_le_bytes(*chunk);
        }
        let mut r = Self::ZERO;
        r[0] = (words[0]) as i32;
        r[1] = ((words[0] >> 26) | (words[1] << 6)) as i32;
        r[2] = ((words[1] >> 19) | (words[2] << 13)) as i32;
        r[3] = ((words[2] >> 13) | (words[3] << 19)) as i32;
        r[4] = (words[3] >> 6) as i32;
        r[5] = (words[4]) as i32;
        r[6] = ((words[4] >> 25) | (words[5] << 7)) as i32;
        r[7] = ((words[5] >> 19) | (words[6] << 13)) as i32;
        r[8] = ((words[6] >> 12) | (words[7] << 20)) as i32;
        r[9] = (words[7] >> 6) as i32;
        r.mask();
        r
    }
}

impl From<Curve25519> for [u8; 32] {
    fn from(mut value: Curve25519) -> Self {
        value.canonical();
        let words = [
            (value[0] as u32) | ((value[1] as u32) << 26),
            ((value[1] as u32) >> 6) | ((value[2] as u32) << 19),
            ((value[2] as u32) >> 13) | ((value[3] as u32) << 13),
            ((value[3] as u32) >> 19) | ((value[4] as u32) << 6),
            (value[5] as u32) | ((value[6] as u32) << 25),
            ((value[6] as u32) >> 7) | ((value[7] as u32) << 19),
            ((value[7] as u32) >> 13) | ((value[8] as u32) << 12),
            ((value[8] as u32) >> 20) | ((value[9] as u32) << 6),
        ];
        let mut bytes = [0u8; 32];
        let (chunks, _) = bytes.as_chunks_mut::<4>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&words[i].to_le_bytes());
        }
        bytes
    }
}

impl Curve25519 {
    pub(super) const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    pub(super) const ZERO: Self = Self([0; 10]);
    pub(super) const SQRT_M1: Self = Self([
        -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686,
        11406482,
    ]);
    const BIAS_25: i32 = 1 << 24;
    const BIAS_26: i32 = 1 << 25;
    const MASK_25: i32 = (1 << 25) - 1;
    const MASK_26: i32 = (1 << 26) - 1;

    pub(crate) const fn from_51bit(value: [u64; 5]) -> Self {
        Self([
            (value[0] as i32) & Self::MASK_26,
            ((value[0] >> 26) as i32) & Self::MASK_25,
            (value[1] as i32) & Self::MASK_26,
            ((value[1] >> 26) as i32) & Self::MASK_25,
            (value[2] as i32) & Self::MASK_26,
            ((value[2] >> 26) as i32) & Self::MASK_25,
            (value[3] as i32) & Self::MASK_26,
            ((value[3] >> 26) as i32) & Self::MASK_25,
            (value[4] as i32) & Self::MASK_26,
            ((value[4] >> 26) as i32) & Self::MASK_25,
        ])
    }

    pub(super) fn swap(a: &mut Self, b: &mut Self, condition: u64) {
        let mask = ((condition != 0) as i32).wrapping_neg();
        for i in 0..10 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    pub(super) fn square(self) -> Self {
        let s0_2 = 2 * self[0];
        let s1_2 = 2 * self[1];
        let s2_2 = 2 * self[2];
        let s3_2 = 2 * self[3];
        let s4_2 = 2 * self[4];
        let s5_2 = 2 * self[5];
        let s6_2 = 2 * self[6];
        let s7_2 = 2 * self[7];
        let s5_38 = 38 * self[5];
        let s6_19 = 19 * self[6];
        let s7_38 = 38 * self[7];
        let s8_19 = 19 * self[8];
        let s9_38 = 38 * self[9];
        let mut t = [0i64; 10];
        t[0] = m(self[0], self[0])
            + m(s1_2, s9_38)
            + m(s2_2, s8_19)
            + m(s3_2, s7_38)
            + m(s4_2, s6_19)
            + m(self[5], s5_38);
        t[1] = m(s0_2, self[1])
            + m(self[2], s9_38)
            + m(s3_2, s8_19)
            + m(self[4], s7_38)
            + m(s5_2, s6_19);
        t[2] = m(s0_2, self[2])
            + m(s1_2, self[1])
            + m(s3_2, s9_38)
            + m(s4_2, s8_19)
            + m(s5_2, s7_38)
            + m(self[6], s6_19);
        t[3] = m(s0_2, self[3])
            + m(s1_2, self[2])
            + m(self[4], s9_38)
            + m(s5_2, s8_19)
            + m(self[6], s7_38);
        t[4] = m(s0_2, self[4])
            + m(s1_2, s3_2)
            + m(self[2], self[2])
            + m(s5_2, s9_38)
            + m(s6_2, s8_19)
            + m(self[7], s7_38);
        t[5] = m(s0_2, self[5])
            + m(s1_2, self[4])
            + m(s2_2, self[3])
            + m(self[6], s9_38)
            + m(s7_2, s8_19);
        t[6] = m(s0_2, self[6])
            + m(s1_2, s5_2)
            + m(s2_2, self[4])
            + m(s3_2, self[3])
            + m(s7_2, s9_38)
            + m(self[8], s8_19);
        t[7] = m(s0_2, self[7])
            + m(s1_2, self[6])
            + m(s2_2, self[5])
            + m(s3_2, self[4])
            + m(self[8], s9_38);
        t[8] = m(s0_2, self[8])
            + m(s1_2, s7_2)
            + m(s2_2, self[6])
            + m(s3_2, s5_2)
            + m(self[4], self[4])
            + m(self[9], s9_38);
        t[9] = m(s0_2, self[9])
            + m(s1_2, self[8])
            + m(s2_2, self[7])
            + m(s3_2, self[6])
            + m(s4_2, self[5]);
        Self::new(t)
    }

    fn new(mut words: [i64; 10]) -> Self {
        let mut carry = (words[0] + Self::BIAS_26 as i64) >> 26;
        words[1] += carry;
        words[0] -= carry << 26;
        carry = (words[4] + Self::BIAS_26 as i64) >> 26;
        words[5] += carry;
        words[4] -= carry << 26;
        carry = (words[1] + Self::BIAS_25 as i64) >> 25;
        words[2] += carry;
        words[1] -= carry << 25;
        carry = (words[5] + Self::BIAS_25 as i64) >> 25;
        words[6] += carry;
        words[5] -= carry << 25;
        carry = (words[2] + Self::BIAS_26 as i64) >> 26;
        words[3] += carry;
        words[2] -= carry << 26;
        carry = (words[6] + Self::BIAS_26 as i64) >> 26;
        words[7] += carry;
        words[6] -= carry << 26;
        carry = (words[3] + Self::BIAS_25 as i64) >> 25;
        words[4] += carry;
        words[3] -= carry << 25;
        carry = (words[7] + Self::BIAS_25 as i64) >> 25;
        words[8] += carry;
        words[7] -= carry << 25;
        carry = (words[4] + Self::BIAS_26 as i64) >> 26;
        words[5] += carry;
        words[4] -= carry << 26;
        carry = (words[8] + Self::BIAS_26 as i64) >> 26;
        words[9] += carry;
        words[8] -= carry << 26;
        carry = (words[9] + Self::BIAS_25 as i64) >> 25;
        words[0] += carry * 19;
        words[9] -= carry << 25;
        carry = (words[0] + Self::BIAS_26 as i64) >> 26;
        words[1] += carry;
        words[0] -= carry << 26;
        Self([
            words[0] as i32,
            words[1] as i32,
            words[2] as i32,
            words[3] as i32,
            words[4] as i32,
            words[5] as i32,
            words[6] as i32,
            words[7] as i32,
            words[8] as i32,
            words[9] as i32,
        ])
    }

    fn reduce(&mut self) {
        *self = Self::new([
            self[0] as i64,
            self[1] as i64,
            self[2] as i64,
            self[3] as i64,
            self[4] as i64,
            self[5] as i64,
            self[6] as i64,
            self[7] as i64,
            self[8] as i64,
            self[9] as i64,
        ]);
    }

    fn carry(&mut self) {
        self[1] += self[0] >> 26;
        self[2] += self[1] >> 25;
        self[3] += self[2] >> 26;
        self[4] += self[3] >> 25;
        self[5] += self[4] >> 26;
        self[6] += self[5] >> 25;
        self[7] += self[6] >> 26;
        self[8] += self[7] >> 25;
        self[9] += self[8] >> 26;
    }

    fn mask(&mut self) {
        self[0] &= Self::MASK_26;
        self[1] &= Self::MASK_25;
        self[2] &= Self::MASK_26;
        self[3] &= Self::MASK_25;
        self[4] &= Self::MASK_26;
        self[5] &= Self::MASK_25;
        self[6] &= Self::MASK_26;
        self[7] &= Self::MASK_25;
        self[8] &= Self::MASK_26;
        self[9] &= Self::MASK_25;
    }

    fn canonical(&mut self) {
        let mut q = (self[0] + 19) >> 26;
        q = (self[1] + q) >> 25;
        q = (self[2] + q) >> 26;
        q = (self[3] + q) >> 25;
        q = (self[4] + q) >> 26;
        q = (self[5] + q) >> 25;
        q = (self[6] + q) >> 26;
        q = (self[7] + q) >> 25;
        q = (self[8] + q) >> 26;
        q = (self[9] + q) >> 25;
        self[0] += 19 * q;
        self.carry();
        self.mask();
    }
}

fn m(x: i32, y: i32) -> i64 {
    (x as i64) * (y as i64)
}
