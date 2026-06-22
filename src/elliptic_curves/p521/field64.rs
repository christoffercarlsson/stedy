use {
    crate::utils::unsigned_mul as m,
    core::{
        array::from_fn,
        ops::{Index, IndexMut},
    },
};

#[derive(Clone, Copy)]
pub struct FieldP521([u64; 9]);

impl Index<usize> for FieldP521 {
    type Output = u64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for FieldP521 {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl FieldP521 {
    pub(super) const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0, 0]);
    pub(super) const ZERO: Self = Self([0; 9]);

    pub(crate) const fn from_limbs(value: [u64; 9]) -> Self {
        Self(value)
    }

    pub(super) fn swap(a: &mut Self, b: &mut Self, condition: u64) {
        let mask = ((condition != 0) as u64).wrapping_neg();
        for i in 0..9 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    pub(super) fn select(a: &Self, b: &Self, condition: u64) -> Self {
        let mut x = *a;
        let mut y = *b;
        Self::swap(&mut x, &mut y, condition);
        x
    }

    pub(super) fn square(self) -> Self {
        let a = &self;
        let a0_2 = a[0] * 2;
        let a1_2 = a[1] * 2;
        let a2_2 = a[2] * 2;
        let a3_2 = a[3] * 2;
        let a5_2 = a[5] * 2;
        let a6_2 = a[6] * 2;
        let a7_2 = a[7] * 2;
        let a8_2 = a[8] * 2;
        let a5_4 = a[5] * 4;
        let a6_4 = a[6] * 4;
        let a7_4 = a[7] * 4;
        let a8_4 = a[8] * 4;
        let mut t = [0u128; 9];
        t[0] = m(a[0], a[0]) + m(a[1], a8_4) + m(a[2], a7_4) + m(a[3], a6_4) + m(a[4], a5_4);
        t[1] = m(a0_2, a[1]) + m(a[5], a5_2) + m(a[2], a8_4) + m(a[3], a7_4) + m(a[4], a6_4);
        t[2] = m(a[1], a[1]) + m(a0_2, a[2]) + m(a[3], a8_4) + m(a[4], a7_4) + m(a[5], a6_4);
        t[3] = m(a1_2, a[2]) + m(a0_2, a[3]) + m(a[6], a6_2) + m(a[4], a8_4) + m(a[5], a7_4);
        t[4] = m(a[2], a[2]) + m(a1_2, a[3]) + m(a0_2, a[4]) + m(a[5], a8_4) + m(a[6], a7_4);
        t[5] = m(a2_2, a[3]) + m(a1_2, a[4]) + m(a0_2, a[5]) + m(a[7], a7_2) + m(a[6], a8_4);
        t[6] = m(a[3], a[3]) + m(a2_2, a[4]) + m(a1_2, a[5]) + m(a0_2, a[6]) + m(a[7], a8_4);
        t[7] = m(a3_2, a[4]) + m(a2_2, a[5]) + m(a1_2, a[6]) + m(a0_2, a[7]) + m(a[8], a8_2);
        t[8] = m(a[4], a[4]) + m(a3_2, a[5]) + m(a2_2, a[6]) + m(a1_2, a[7]) + m(a0_2, a[8]);
        Self::reduce_wide(t)
    }

    pub(super) fn mul(self, rhs: Self) -> Self {
        let r1_2 = rhs[1] * 2;
        let r2_2 = rhs[2] * 2;
        let r3_2 = rhs[3] * 2;
        let r4_2 = rhs[4] * 2;
        let r5_2 = rhs[5] * 2;
        let r6_2 = rhs[6] * 2;
        let r7_2 = rhs[7] * 2;
        let r8_2 = rhs[8] * 2;
        let mut t = [0u128; 9];
        t[0] = m(self[0], rhs[0])
            + m(self[1], r8_2)
            + m(self[2], r7_2)
            + m(self[3], r6_2)
            + m(self[4], r5_2)
            + m(self[5], r4_2)
            + m(self[6], r3_2)
            + m(self[7], r2_2)
            + m(self[8], r1_2);
        t[1] = m(self[0], rhs[1])
            + m(self[1], rhs[0])
            + m(self[2], r8_2)
            + m(self[3], r7_2)
            + m(self[4], r6_2)
            + m(self[5], r5_2)
            + m(self[6], r4_2)
            + m(self[7], r3_2)
            + m(self[8], r2_2);
        t[2] = m(self[0], rhs[2])
            + m(self[1], rhs[1])
            + m(self[2], rhs[0])
            + m(self[3], r8_2)
            + m(self[4], r7_2)
            + m(self[5], r6_2)
            + m(self[6], r5_2)
            + m(self[7], r4_2)
            + m(self[8], r3_2);
        t[3] = m(self[0], rhs[3])
            + m(self[1], rhs[2])
            + m(self[2], rhs[1])
            + m(self[3], rhs[0])
            + m(self[4], r8_2)
            + m(self[5], r7_2)
            + m(self[6], r6_2)
            + m(self[7], r5_2)
            + m(self[8], r4_2);
        t[4] = m(self[0], rhs[4])
            + m(self[1], rhs[3])
            + m(self[2], rhs[2])
            + m(self[3], rhs[1])
            + m(self[4], rhs[0])
            + m(self[5], r8_2)
            + m(self[6], r7_2)
            + m(self[7], r6_2)
            + m(self[8], r5_2);
        t[5] = m(self[0], rhs[5])
            + m(self[1], rhs[4])
            + m(self[2], rhs[3])
            + m(self[3], rhs[2])
            + m(self[4], rhs[1])
            + m(self[5], rhs[0])
            + m(self[6], r8_2)
            + m(self[7], r7_2)
            + m(self[8], r6_2);
        t[6] = m(self[0], rhs[6])
            + m(self[1], rhs[5])
            + m(self[2], rhs[4])
            + m(self[3], rhs[3])
            + m(self[4], rhs[2])
            + m(self[5], rhs[1])
            + m(self[6], rhs[0])
            + m(self[7], r8_2)
            + m(self[8], r7_2);
        t[7] = m(self[0], rhs[7])
            + m(self[1], rhs[6])
            + m(self[2], rhs[5])
            + m(self[3], rhs[4])
            + m(self[4], rhs[3])
            + m(self[5], rhs[2])
            + m(self[6], rhs[1])
            + m(self[7], rhs[0])
            + m(self[8], r8_2);
        t[8] = m(self[0], rhs[8])
            + m(self[1], rhs[7])
            + m(self[2], rhs[6])
            + m(self[3], rhs[5])
            + m(self[4], rhs[4])
            + m(self[5], rhs[3])
            + m(self[6], rhs[2])
            + m(self[7], rhs[1])
            + m(self[8], rhs[0]);
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
        let result =
            diff[0] | diff[1] | diff[2] | diff[3] | diff[4] | diff[5] | diff[6] | diff[7] | diff[8];
        result == 0
    }

    pub(super) fn from_u32(n: u32) -> Self {
        let mut result = Self::ZERO;
        result[0] = n as u64;
        result.reduce();
        result
    }

    pub(super) fn from_bytes(bytes: &[u8; 66]) -> Self {
        let mut bytes = *bytes;
        bytes.reverse();
        let mut words = [0u64; 8];
        let (chunks, remainder) = bytes.as_chunks::<8>();
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u64::from_le_bytes(*chunk);
        }
        let top_word = (remainder[0] as u64) | ((remainder[1] as u64 & 1) << 8);
        let mut result = Self::ZERO;
        result[0] = words[0] & Self::MASK;
        result[1] = ((words[0] >> 58) | (words[1] << 6)) & Self::MASK;
        result[2] = ((words[1] >> 52) | (words[2] << 12)) & Self::MASK;
        result[3] = ((words[2] >> 46) | (words[3] << 18)) & Self::MASK;
        result[4] = ((words[3] >> 40) | (words[4] << 24)) & Self::MASK;
        result[5] = ((words[4] >> 34) | (words[5] << 30)) & Self::MASK;
        result[6] = ((words[5] >> 28) | (words[6] << 36)) & Self::MASK;
        result[7] = ((words[6] >> 22) | (words[7] << 42)) & Self::MASK;
        result[8] = ((words[7] >> 16) | (top_word << 48)) & Self::TOP_MASK;
        result
    }

    pub(super) fn to_bytes(mut self) -> [u8; 66] {
        self.canonical();
        let words = [
            self[0] | (self[1] << 58),
            (self[1] >> 6) | (self[2] << 52),
            (self[2] >> 12) | (self[3] << 46),
            (self[3] >> 18) | (self[4] << 40),
            (self[4] >> 24) | (self[5] << 34),
            (self[5] >> 30) | (self[6] << 28),
            (self[6] >> 36) | (self[7] << 22),
            (self[7] >> 42) | (self[8] << 16),
        ];
        let mut bytes = [0u8; 66];
        let (chunks, remainder) = bytes.as_chunks_mut::<8>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&words[i].to_le_bytes());
        }
        remainder[0] = (self[8] >> 48) as u8;
        remainder[1] = (self[8] >> 56) as u8 & 1;
        bytes.reverse();
        bytes
    }
}

impl FieldP521 {
    const MASK: u64 = (1 << 58) - 1;
    const TOP_MASK: u64 = (1 << 57) - 1;
    const P2: Self = Self([
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::TOP_MASK << 1,
    ]);

    const fn reduce_wide(mut words: [u128; 9]) -> Self {
        words[1] += ((words[0] >> 58) as u64) as u128;
        words[2] += ((words[1] >> 58) as u64) as u128;
        words[3] += ((words[2] >> 58) as u64) as u128;
        words[4] += ((words[3] >> 58) as u64) as u128;
        words[5] += ((words[4] >> 58) as u64) as u128;
        words[6] += ((words[5] >> 58) as u64) as u128;
        words[7] += ((words[6] >> 58) as u64) as u128;
        words[8] += ((words[7] >> 58) as u64) as u128;
        let carry = (words[8] >> 57) as u64;
        let mut t = [
            (words[0] as u64) & Self::MASK,
            (words[1] as u64) & Self::MASK,
            (words[2] as u64) & Self::MASK,
            (words[3] as u64) & Self::MASK,
            (words[4] as u64) & Self::MASK,
            (words[5] as u64) & Self::MASK,
            (words[6] as u64) & Self::MASK,
            (words[7] as u64) & Self::MASK,
            (words[8] as u64) & Self::TOP_MASK,
        ];
        t[0] += carry;
        t[1] += t[0] >> 58;
        t[2] += t[1] >> 58;
        t[0] &= Self::MASK;
        t[1] &= Self::MASK;
        Self(t)
    }

    fn reduce(&mut self) {
        self.carry();
        let carry = self[8] >> 57;
        self.mask();
        self[0] += carry;
        self[1] += self[0] >> 58;
        self[2] += self[1] >> 58;
        self[0] &= Self::MASK;
        self[1] &= Self::MASK;
    }

    fn carry(&mut self) {
        self[1] += self[0] >> 58;
        self[2] += self[1] >> 58;
        self[3] += self[2] >> 58;
        self[4] += self[3] >> 58;
        self[5] += self[4] >> 58;
        self[6] += self[5] >> 58;
        self[7] += self[6] >> 58;
        self[8] += self[7] >> 58;
    }

    fn mask(&mut self) {
        self[0] &= Self::MASK;
        self[1] &= Self::MASK;
        self[2] &= Self::MASK;
        self[3] &= Self::MASK;
        self[4] &= Self::MASK;
        self[5] &= Self::MASK;
        self[6] &= Self::MASK;
        self[7] &= Self::MASK;
        self[8] &= Self::TOP_MASK;
    }

    fn canonical(&mut self) {
        let mut reduced = *self;
        reduced[0] += 1;
        reduced.carry();
        reduced[8] = reduced[8].wrapping_sub(1 << 57);
        let borrow = reduced[8] >> 63;
        reduced.mask();
        *self = Self::select(&reduced, self, borrow);
    }
}
