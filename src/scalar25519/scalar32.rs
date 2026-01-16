use core::ops::{Add, Index, IndexMut, Neg};

#[derive(Clone, Copy)]
pub struct Scalar25519([u32; 10]);

impl Index<usize> for Scalar25519 {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Scalar25519 {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl Add for Scalar25519 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut s = Self::ZERO;
        s[0] = self[0] + rhs[0];
        s[1] = self[1] + rhs[1];
        s[2] = self[2] + rhs[2];
        s[3] = self[3] + rhs[3];
        s[4] = self[4] + rhs[4];
        s[5] = self[5] + rhs[5];
        s[6] = self[6] + rhs[6];
        s[7] = self[7] + rhs[7];
        s[8] = self[8] + rhs[8];
        s[9] = self[9] + rhs[9];
        s[1] += s[0] >> 26;
        s[2] += s[1] >> 26;
        s[3] += s[2] >> 26;
        s[4] += s[3] >> 26;
        s[5] += s[4] >> 26;
        s[6] += s[5] >> 26;
        s[7] += s[6] >> 26;
        s[8] += s[7] >> 26;
        s[9] += s[8] >> 26;
        s.mask();
        s.reduce();
        s
    }
}

impl Neg for Scalar25519 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut diff = Self::ZERO;
        let mut borrow = 0u32;
        for i in 0..10 {
            let (d1, b1) = Self::L[i].overflowing_sub(self[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            diff[i] = d2 & Self::MASK;
            borrow = (b1 | b2) as u32;
        }
        let is_zero = ((self[0]
            | self[1]
            | self[2]
            | self[3]
            | self[4]
            | self[5]
            | self[6]
            | self[7]
            | self[8]
            | self[9])
            == 0) as u32;
        Self::select(&diff, &Self::ZERO, is_zero)
    }
}

impl From<[u8; 32]> for Scalar25519 {
    fn from(value: [u8; 32]) -> Self {
        let (chunks, _) = value.as_chunks::<4>();
        let mut words = [0u32; 8];
        for (i, chunk) in chunks.iter().enumerate().take(8) {
            words[i] = u32::from_le_bytes(*chunk);
        }
        let mut s = Self::ZERO;
        s[0] = words[0] & Self::MASK;
        s[1] = ((words[0] >> 26) | (words[1] << 6)) & Self::MASK;
        s[2] = ((words[1] >> 20) | (words[2] << 12)) & Self::MASK;
        s[3] = ((words[2] >> 14) | (words[3] << 18)) & Self::MASK;
        s[4] = ((words[3] >> 8) | (words[4] << 24)) & Self::MASK;
        s[5] = (words[4] >> 2) & Self::MASK;
        s[6] = ((words[4] >> 28) | (words[5] << 4)) & Self::MASK;
        s[7] = ((words[5] >> 22) | (words[6] << 10)) & Self::MASK;
        s[8] = ((words[6] >> 16) | (words[7] << 16)) & Self::MASK;
        s[9] = (words[7] >> 10) & Self::TOP_MASK;
        s
    }
}

impl From<[u8; 64]> for Scalar25519 {
    fn from(value: [u8; 64]) -> Self {
        let (chunks, _) = value.as_chunks::<4>();
        let mut words = [0u32; 16];
        for (i, chunk) in chunks.iter().enumerate().take(16) {
            words[i] = u32::from_le_bytes(*chunk);
        }
        let mut lo = Self::ZERO;
        let mut hi = Self::ZERO;
        lo[0] = words[0] & Self::MASK;
        lo[1] = ((words[0] >> 26) | (words[1] << 6)) & Self::MASK;
        lo[2] = ((words[1] >> 20) | (words[2] << 12)) & Self::MASK;
        lo[3] = ((words[2] >> 14) | (words[3] << 18)) & Self::MASK;
        lo[4] = ((words[3] >> 8) | (words[4] << 24)) & Self::MASK;
        lo[5] = (words[4] >> 2) & Self::MASK;
        lo[6] = ((words[4] >> 28) | (words[5] << 4)) & Self::MASK;
        lo[7] = ((words[5] >> 22) | (words[6] << 10)) & Self::MASK;
        lo[8] = ((words[6] >> 16) | (words[7] << 16)) & Self::MASK;
        lo[9] = ((words[7] >> 10) | (words[8] << 22)) & Self::MASK;
        hi[0] = (words[8] >> 4) & Self::MASK;
        hi[1] = ((words[8] >> 30) | (words[9] << 2)) & Self::MASK;
        hi[2] = ((words[9] >> 24) | (words[10] << 8)) & Self::MASK;
        hi[3] = ((words[10] >> 18) | (words[11] << 14)) & Self::MASK;
        hi[4] = ((words[11] >> 12) | (words[12] << 20)) & Self::MASK;
        hi[5] = (words[12] >> 6) & Self::MASK;
        hi[6] = words[13] & Self::MASK;
        hi[7] = ((words[13] >> 26) | (words[14] << 6)) & Self::MASK;
        hi[8] = ((words[14] >> 20) | (words[15] << 12)) & Self::MASK;
        hi[9] = words[15] >> 14;
        lo = lo.montgomery_mul(Self::R);
        hi = hi.montgomery_mul(Self::R2);
        hi + lo
    }
}

impl From<Scalar25519> for [u8; 32] {
    fn from(value: Scalar25519) -> Self {
        let words = [
            value[0] | (value[1] << 26),
            (value[1] >> 6) | (value[2] << 20),
            (value[2] >> 12) | (value[3] << 14),
            (value[3] >> 18) | (value[4] << 8),
            (value[4] >> 24) | (value[5] << 2) | (value[6] << 28),
            (value[6] >> 4) | (value[7] << 22),
            (value[7] >> 10) | (value[8] << 16),
            (value[8] >> 16) | (value[9] << 10),
        ];
        let mut bytes = [0u8; 32];
        let (chunks, _) = bytes.as_chunks_mut::<4>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&words[i].to_le_bytes());
        }
        bytes
    }
}

impl Scalar25519 {
    const L: Self = Self([
        16110573, 10012311, 30238081, 58362846, 1367801, 0, 0, 0, 0, 262144,
    ]);
    const LFACTOR: u32 = 39091739;
    const MASK: u32 = (1 << 26) - 1;
    const TOP_MASK: u32 = (1 << 22) - 1;
    const R: Self = Self([
        52553453, 64106329, 6808666, 15641963, 53863707, 67108858, 67108863, 67108863, 67108863,
        262143,
    ]);
    pub(super) const R2: Self = Self([
        22204731, 41195898, 29271711, 56160709, 57177604, 24090994, 54337919, 16202673, 58470554,
        151622,
    ]);
    const ZERO: Self = Self([0; 10]);

    fn mask(&mut self) {
        self[0] &= Self::MASK;
        self[1] &= Self::MASK;
        self[2] &= Self::MASK;
        self[3] &= Self::MASK;
        self[4] &= Self::MASK;
        self[5] &= Self::MASK;
        self[6] &= Self::MASK;
        self[7] &= Self::MASK;
        self[8] &= Self::MASK;
        self[9] &= Self::MASK;
    }

    pub(super) fn montgomery_mul(self, rhs: Self) -> Self {
        let mut t = [0u64; 20];
        t[0] = m(self[0], rhs[0]);
        t[1] = m(self[0], rhs[1]) + m(self[1], rhs[0]);
        t[2] = m(self[0], rhs[2]) + m(self[1], rhs[1]) + m(self[2], rhs[0]);
        t[3] = m(self[0], rhs[3]) + m(self[1], rhs[2]) + m(self[2], rhs[1]) + m(self[3], rhs[0]);
        t[4] = m(self[0], rhs[4])
            + m(self[1], rhs[3])
            + m(self[2], rhs[2])
            + m(self[3], rhs[1])
            + m(self[4], rhs[0]);
        t[5] = m(self[0], rhs[5])
            + m(self[1], rhs[4])
            + m(self[2], rhs[3])
            + m(self[3], rhs[2])
            + m(self[4], rhs[1])
            + m(self[5], rhs[0]);
        t[6] = m(self[0], rhs[6])
            + m(self[1], rhs[5])
            + m(self[2], rhs[4])
            + m(self[3], rhs[3])
            + m(self[4], rhs[2])
            + m(self[5], rhs[1])
            + m(self[6], rhs[0]);
        t[7] = m(self[0], rhs[7])
            + m(self[1], rhs[6])
            + m(self[2], rhs[5])
            + m(self[3], rhs[4])
            + m(self[4], rhs[3])
            + m(self[5], rhs[2])
            + m(self[6], rhs[1])
            + m(self[7], rhs[0]);
        t[8] = m(self[0], rhs[8])
            + m(self[1], rhs[7])
            + m(self[2], rhs[6])
            + m(self[3], rhs[5])
            + m(self[4], rhs[4])
            + m(self[5], rhs[3])
            + m(self[6], rhs[2])
            + m(self[7], rhs[1])
            + m(self[8], rhs[0]);
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
        t[10] = m(self[1], rhs[9])
            + m(self[2], rhs[8])
            + m(self[3], rhs[7])
            + m(self[4], rhs[6])
            + m(self[5], rhs[5])
            + m(self[6], rhs[4])
            + m(self[7], rhs[3])
            + m(self[8], rhs[2])
            + m(self[9], rhs[1]);
        t[11] = m(self[2], rhs[9])
            + m(self[3], rhs[8])
            + m(self[4], rhs[7])
            + m(self[5], rhs[6])
            + m(self[6], rhs[5])
            + m(self[7], rhs[4])
            + m(self[8], rhs[3])
            + m(self[9], rhs[2]);
        t[12] = m(self[3], rhs[9])
            + m(self[4], rhs[8])
            + m(self[5], rhs[7])
            + m(self[6], rhs[6])
            + m(self[7], rhs[5])
            + m(self[8], rhs[4])
            + m(self[9], rhs[3]);
        t[13] = m(self[4], rhs[9])
            + m(self[5], rhs[8])
            + m(self[6], rhs[7])
            + m(self[7], rhs[6])
            + m(self[8], rhs[5])
            + m(self[9], rhs[4]);
        t[14] = m(self[5], rhs[9])
            + m(self[6], rhs[8])
            + m(self[7], rhs[7])
            + m(self[8], rhs[6])
            + m(self[9], rhs[5]);
        t[15] = m(self[6], rhs[9]) + m(self[7], rhs[8]) + m(self[8], rhs[7]) + m(self[9], rhs[6]);
        t[16] = m(self[7], rhs[9]) + m(self[8], rhs[8]) + m(self[9], rhs[7]);
        t[17] = m(self[8], rhs[9]) + m(self[9], rhs[8]);
        t[18] = m(self[9], rhs[9]);
        Self::round(&mut t, 0);
        Self::round(&mut t, 1);
        Self::round(&mut t, 2);
        Self::round(&mut t, 3);
        Self::round(&mut t, 4);
        Self::round(&mut t, 5);
        Self::round(&mut t, 6);
        Self::round(&mut t, 7);
        Self::round(&mut t, 8);
        Self::round(&mut t, 9);
        t[11] += t[10] >> 26;
        t[12] += t[11] >> 26;
        t[13] += t[12] >> 26;
        t[14] += t[13] >> 26;
        t[15] += t[14] >> 26;
        t[16] += t[15] >> 26;
        t[17] += t[16] >> 26;
        t[18] += t[17] >> 26;
        t[19] += t[18] >> 26;
        let mut s = Self([
            t[10] as u32,
            t[11] as u32,
            t[12] as u32,
            t[13] as u32,
            t[14] as u32,
            t[15] as u32,
            t[16] as u32,
            t[17] as u32,
            t[18] as u32,
            t[19] as u32,
        ]);
        s.mask();
        s.reduce();
        s
    }

    fn round(t: &mut [u64; 20], i: usize) {
        let x = ((t[i] as u32).wrapping_mul(Self::LFACTOR) & Self::MASK) as u64;
        t[i] += x * Self::L[0] as u64;
        t[i + 1] += x * Self::L[1] as u64;
        t[i + 2] += x * Self::L[2] as u64;
        t[i + 3] += x * Self::L[3] as u64;
        t[i + 4] += x * Self::L[4] as u64;
        t[i + 9] += x * Self::L[9] as u64;
        t[i + 1] += t[i] >> 26;
    }

    fn reduce(&mut self) {
        let mut diff = Self::ZERO;
        let mut borrow = 0u32;
        for i in 0..10 {
            let (d1, b1) = self[i].overflowing_sub(Self::L[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            diff[i] = d2 & Self::MASK;
            borrow = (b1 | b2) as u32;
        }
        *self = Self::select(&diff, self, borrow);
    }

    fn select(a: &Self, b: &Self, condition: u32) -> Self {
        let mask = ((condition != 0) as u32).wrapping_neg();
        Self([
            a[0] & !mask | b[0] & mask,
            a[1] & !mask | b[1] & mask,
            a[2] & !mask | b[2] & mask,
            a[3] & !mask | b[3] & mask,
            a[4] & !mask | b[4] & mask,
            a[5] & !mask | b[5] & mask,
            a[6] & !mask | b[6] & mask,
            a[7] & !mask | b[7] & mask,
            a[8] & !mask | b[8] & mask,
            a[9] & !mask | b[9] & mask,
        ])
    }
}

fn m(x: u32, y: u32) -> u64 {
    (x as u64) * (y as u64)
}
