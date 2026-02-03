use {
    crate::utils::unsigned_mul as m,
    core::{
        array::from_fn,
        ops::{Index, IndexMut},
    },
};

#[derive(Clone, Copy)]
pub struct Field25519([u64; 5]);

impl Index<usize> for Field25519 {
    type Output = u64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Field25519 {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl Field25519 {
    pub(super) const ONE: Self = Self([1, 0, 0, 0, 0]);
    pub(super) const ZERO: Self = Self([0; 5]);

    pub(crate) const fn from_limbs(value: [u64; 5]) -> Self {
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
        Self::reduce_wide(t)
    }

    pub(super) fn mul(self, rhs: Self) -> Self {
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
        Self::reduce_wide(t)
    }

    pub(super) fn add(self, rhs: Self) -> Self {
        let mut result = Self(from_fn(|i| self[i] + rhs[i]));
        result.reduce();
        result
    }

    pub(super) fn sub(self, rhs: Self) -> Self {
        let mut result = Self(from_fn(|i| Self::P2[i] + self[i] - rhs[i]));
        result.reduce();
        result
    }

    pub(super) fn neg(self) -> Self {
        let mut result = Self(from_fn(|i| Self::P2[i] - self[i]));
        result.reduce();
        result
    }

    pub(super) fn eq(&self, other: &Self) -> bool {
        let mut diff = self.sub(*other);
        diff.canonical();
        let result = diff[0] | diff[1] | diff[2] | diff[3] | diff[4];
        result == 0
    }

    pub(super) fn from_u32(n: u32) -> Self {
        let mut result = Self::ZERO;
        result[0] = n as u64;
        result.reduce();
        result
    }

    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut words = [0u64; 4];
        let (chunks, _) = bytes.as_chunks::<8>();
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u64::from_le_bytes(*chunk);
        }
        let mut result = Self::ZERO;
        result[0] = words[0];
        result[1] = (words[0] >> 51) | (words[1] << 13);
        result[2] = (words[1] >> 38) | (words[2] << 26);
        result[3] = (words[2] >> 25) | (words[3] << 39);
        result[4] = words[3] >> 12;
        result.mask();
        result
    }

    pub(super) fn to_bytes(mut self) -> [u8; 32] {
        self.canonical();
        let words = [
            self[0] | (self[1] << 51),
            self[1] >> 13 | (self[2] << 38),
            self[2] >> 26 | (self[3] << 25),
            self[3] >> 39 | (self[4] << 12),
        ];
        let mut bytes = [0u8; 32];
        let (chunks, _) = bytes.as_chunks_mut::<8>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&words[i].to_le_bytes());
        }
        bytes
    }
}

impl Field25519 {
    const MASK: u64 = (1 << 51) - 1;
    const P2: Self = Self([
        (Self::MASK << 1) - 36,
        (Self::MASK << 1),
        (Self::MASK << 1),
        (Self::MASK << 1),
        (Self::MASK << 1),
    ]);

    const fn reduce_wide(mut words: [u128; 5]) -> Self {
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
        let mut reduced = *self;
        reduced[0] += 19;
        reduced.carry();
        reduced[4] = reduced[4].wrapping_sub(1 << 51);
        let borrow = reduced[4] >> 63;
        reduced.mask();
        *self = Self::select(&reduced, self, borrow);
    }
}
