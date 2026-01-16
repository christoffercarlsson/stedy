use core::ops::{Add, Index, IndexMut, Neg};

#[derive(Clone, Copy)]
pub struct Scalar25519([u64; 5]);

impl Index<usize> for Scalar25519 {
    type Output = u64;

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
        s[1] += s[0] >> 52;
        s[2] += s[1] >> 52;
        s[3] += s[2] >> 52;
        s[4] += s[3] >> 52;
        s.mask();
        s.reduce();
        s
    }
}

impl Neg for Scalar25519 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut diff = Self::ZERO;
        let mut borrow = 0u64;
        for i in 0..5 {
            let (d1, b1) = Self::L[i].overflowing_sub(self[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            diff[i] = d2 & Self::MASK;
            borrow = (b1 | b2) as u64;
        }
        let is_zero = ((self[0] | self[1] | self[2] | self[3] | self[4]) == 0) as u64;
        Self::select(&diff, &Self::ZERO, is_zero)
    }
}

impl From<[u8; 32]> for Scalar25519 {
    fn from(value: [u8; 32]) -> Self {
        let words = [
            u64::from_le_bytes(value[0..8].try_into().unwrap()),
            u64::from_le_bytes(value[8..16].try_into().unwrap()),
            u64::from_le_bytes(value[16..24].try_into().unwrap()),
            u64::from_le_bytes(value[24..32].try_into().unwrap()),
        ];
        let mut s = Self::ZERO;
        s[0] = words[0] & Self::MASK;
        s[1] = ((words[0] >> 52) | (words[1] << 12)) & Self::MASK;
        s[2] = ((words[1] >> 40) | (words[2] << 24)) & Self::MASK;
        s[3] = ((words[2] >> 28) | (words[3] << 36)) & Self::MASK;
        s[4] = (words[3] >> 16) & Self::TOP_MASK;
        s
    }
}

impl From<[u8; 64]> for Scalar25519 {
    fn from(value: [u8; 64]) -> Self {
        let words = [
            u64::from_le_bytes(value[0..8].try_into().unwrap()),
            u64::from_le_bytes(value[8..16].try_into().unwrap()),
            u64::from_le_bytes(value[16..24].try_into().unwrap()),
            u64::from_le_bytes(value[24..32].try_into().unwrap()),
            u64::from_le_bytes(value[32..40].try_into().unwrap()),
            u64::from_le_bytes(value[40..48].try_into().unwrap()),
            u64::from_le_bytes(value[48..56].try_into().unwrap()),
            u64::from_le_bytes(value[56..64].try_into().unwrap()),
        ];
        let mut lo = Self::ZERO;
        let mut hi = Self::ZERO;
        lo[0] = words[0] & Self::MASK;
        lo[1] = ((words[0] >> 52) | (words[1] << 12)) & Self::MASK;
        lo[2] = ((words[1] >> 40) | (words[2] << 24)) & Self::MASK;
        lo[3] = ((words[2] >> 28) | (words[3] << 36)) & Self::MASK;
        lo[4] = ((words[3] >> 16) | (words[4] << 48)) & Self::MASK;
        hi[0] = (words[4] >> 4) & Self::MASK;
        hi[1] = ((words[4] >> 56) | (words[5] << 8)) & Self::MASK;
        hi[2] = ((words[5] >> 44) | (words[6] << 20)) & Self::MASK;
        hi[3] = ((words[6] >> 32) | (words[7] << 32)) & Self::MASK;
        hi[4] = words[7] >> 20;
        lo = lo.montgomery_mul(Self::R);
        hi = hi.montgomery_mul(Self::R2);
        hi + lo
    }
}

impl From<Scalar25519> for [u8; 32] {
    fn from(value: Scalar25519) -> Self {
        let words = [
            value[0] | (value[1] << 52),
            (value[1] >> 12) | (value[2] << 40),
            (value[2] >> 24) | (value[3] << 28),
            (value[3] >> 36) | (value[4] << 16),
        ];
        let mut bytes = [0u8; 32];
        let (chunks, _) = bytes.as_chunks_mut::<8>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&words[i].to_le_bytes());
        }
        bytes
    }
}

impl Scalar25519 {
    const L: Self = Self([
        671914833335277,
        3916664325105025,
        1367801,
        0,
        17592186044416,
    ]);
    const LFACTOR: u64 = 1439961107955227;
    const MASK: u64 = (1 << 52) - 1;
    const TOP_MASK: u64 = (1 << 48) - 1;
    const R: Self = Self([
        4302102966953709,
        1049714374468698,
        4503599278581019,
        4503599627370495,
        17592186044415,
    ]);
    pub(super) const R2: Self = Self([
        2764609938444603,
        3768881411696287,
        1616719297148420,
        1087343033131391,
        10175238647962,
    ]);
    const ZERO: Self = Self([0; 5]);

    fn mask(&mut self) {
        self[0] &= Self::MASK;
        self[1] &= Self::MASK;
        self[2] &= Self::MASK;
        self[3] &= Self::MASK;
        self[4] &= Self::MASK;
    }

    pub(super) fn montgomery_mul(self, rhs: Self) -> Self {
        let mut t = [0u128; 10];
        t[0] = m(self[0], rhs[0]);
        t[1] = m(self[0], rhs[1]) + m(self[1], rhs[0]);
        t[2] = m(self[0], rhs[2]) + m(self[1], rhs[1]) + m(self[2], rhs[0]);
        t[3] = m(self[0], rhs[3]) + m(self[1], rhs[2]) + m(self[2], rhs[1]) + m(self[3], rhs[0]);
        t[4] = m(self[0], rhs[4])
            + m(self[1], rhs[3])
            + m(self[2], rhs[2])
            + m(self[3], rhs[1])
            + m(self[4], rhs[0]);
        t[5] = m(self[1], rhs[4]) + m(self[2], rhs[3]) + m(self[3], rhs[2]) + m(self[4], rhs[1]);
        t[6] = m(self[2], rhs[4]) + m(self[3], rhs[3]) + m(self[4], rhs[2]);
        t[7] = m(self[3], rhs[4]) + m(self[4], rhs[3]);
        t[8] = m(self[4], rhs[4]);
        Self::round(&mut t, 0);
        Self::round(&mut t, 1);
        Self::round(&mut t, 2);
        Self::round(&mut t, 3);
        Self::round(&mut t, 4);
        t[6] += t[5] >> 52;
        t[7] += t[6] >> 52;
        t[8] += t[7] >> 52;
        t[9] += t[8] >> 52;
        let mut s = Self([
            t[5] as u64,
            t[6] as u64,
            t[7] as u64,
            t[8] as u64,
            t[9] as u64,
        ]);
        s.mask();
        s.reduce();
        s
    }

    fn round(t: &mut [u128; 10], i: usize) {
        let x = ((t[i] as u64).wrapping_mul(Self::LFACTOR) & Self::MASK) as u128;
        t[i] += x * Self::L[0] as u128;
        t[i + 1] += x * Self::L[1] as u128;
        t[i + 2] += x * Self::L[2] as u128;
        t[i + 4] += x * Self::L[4] as u128;
        t[i + 1] += t[i] >> 52;
    }

    fn reduce(&mut self) {
        let mut diff = Self::ZERO;
        let mut borrow = 0u64;
        for i in 0..5 {
            let (d1, b1) = self[i].overflowing_sub(Self::L[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            diff[i] = d2 & Self::MASK;
            borrow = (b1 | b2) as u64;
        }
        *self = Self::select(&diff, self, borrow);
    }

    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        let mask = ((condition != 0) as u64).wrapping_neg();
        Self([
            a[0] & !mask | b[0] & mask,
            a[1] & !mask | b[1] & mask,
            a[2] & !mask | b[2] & mask,
            a[3] & !mask | b[3] & mask,
            a[4] & !mask | b[4] & mask,
        ])
    }
}

fn m(x: u64, y: u64) -> u128 {
    (x as u128) * (y as u128)
}
