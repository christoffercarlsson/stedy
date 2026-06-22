use {
    crate::utils::unsigned_mul as m,
    core::{
        array::from_fn,
        ops::{Index, IndexMut},
    },
};

#[derive(Clone, Copy)]
pub struct FieldP521([u32; 18]);

impl Index<usize> for FieldP521 {
    type Output = u32;
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
    pub(super) const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    pub(super) const ZERO: Self = Self([0; 18]);

    pub(crate) const fn from_limbs(value: [u64; 9]) -> Self {
        let mask = (1u32 << 29) - 1;
        let mut result = [0u32; 18];
        let mut i = 0;
        while i < 9 {
            result[i * 2] = (value[i] as u32) & mask;
            result[i * 2 + 1] = ((value[i] >> 29) as u32) & mask;
            i += 1;
        }
        Self(result)
    }

    pub(super) fn swap(a: &mut Self, b: &mut Self, condition: u64) {
        let mask = ((condition != 0) as u32).wrapping_neg();
        for i in 0..18 {
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
        let a4_2 = a[4] * 2;
        let a5_2 = a[5] * 2;
        let a6_2 = a[6] * 2;
        let a7_2 = a[7] * 2;
        let a8_2 = a[8] * 2;
        let a9_2 = a[9] * 2;
        let a10_4 = a[10] * 4;
        let a11_4 = a[11] * 4;
        let a12_4 = a[12] * 4;
        let a13_4 = a[13] * 4;
        let a14_4 = a[14] * 4;
        let a15_4 = a[15] * 4;
        let a16_4 = a[16] * 4;
        let a17_4 = a[17] * 4;
        let mut t = [0u64; 18];
        t[0] = m(a[0], a[0])
            + m(a[1], a17_4)
            + m(a[2], a16_4)
            + m(a[3], a15_4)
            + m(a[4], a14_4)
            + m(a[5], a13_4)
            + m(a[6], a12_4)
            + m(a[7], a11_4)
            + m(a[8], a10_4)
            + m(a[9], a9_2);
        t[1] = m(a0_2, a[1])
            + m(a[2], a17_4)
            + m(a[3], a16_4)
            + m(a[4], a15_4)
            + m(a[5], a14_4)
            + m(a[6], a13_4)
            + m(a[7], a12_4)
            + m(a[8], a11_4)
            + m(a[9], a10_4);
        t[2] = m(a[1], a[1])
            + m(a0_2, a[2])
            + m(a[3], a17_4)
            + m(a[4], a16_4)
            + m(a[5], a15_4)
            + m(a[6], a14_4)
            + m(a[7], a13_4)
            + m(a[8], a12_4)
            + m(a[9], a11_4)
            + m(a[10], a[10]) * 2;
        t[3] = m(a0_2, a[3])
            + m(a1_2, a[2])
            + m(a[4], a17_4)
            + m(a[5], a16_4)
            + m(a[6], a15_4)
            + m(a[7], a14_4)
            + m(a[8], a13_4)
            + m(a[9], a12_4)
            + m(a[10], a11_4);
        t[4] = m(a[2], a[2])
            + m(a0_2, a[4])
            + m(a1_2, a[3])
            + m(a[5], a17_4)
            + m(a[6], a16_4)
            + m(a[7], a15_4)
            + m(a[8], a14_4)
            + m(a[9], a13_4)
            + m(a[10], a12_4)
            + m(a[11], a[11]) * 2;
        t[5] = m(a0_2, a[5])
            + m(a1_2, a[4])
            + m(a2_2, a[3])
            + m(a[6], a17_4)
            + m(a[7], a16_4)
            + m(a[8], a15_4)
            + m(a[9], a14_4)
            + m(a[10], a13_4)
            + m(a[11], a12_4);
        t[6] = m(a[3], a[3])
            + m(a0_2, a[6])
            + m(a1_2, a[5])
            + m(a2_2, a[4])
            + m(a[7], a17_4)
            + m(a[8], a16_4)
            + m(a[9], a15_4)
            + m(a[10], a14_4)
            + m(a[11], a13_4)
            + m(a[12], a[12]) * 2;
        t[7] = m(a0_2, a[7])
            + m(a1_2, a[6])
            + m(a2_2, a[5])
            + m(a3_2, a[4])
            + m(a[8], a17_4)
            + m(a[9], a16_4)
            + m(a[10], a15_4)
            + m(a[11], a14_4)
            + m(a[12], a13_4);
        t[8] = m(a[4], a[4])
            + m(a0_2, a[8])
            + m(a1_2, a[7])
            + m(a2_2, a[6])
            + m(a3_2, a[5])
            + m(a[9], a17_4)
            + m(a[10], a16_4)
            + m(a[11], a15_4)
            + m(a[12], a14_4)
            + m(a[13], a[13]) * 2;
        t[9] = m(a0_2, a[9])
            + m(a1_2, a[8])
            + m(a2_2, a[7])
            + m(a3_2, a[6])
            + m(a4_2, a[5])
            + m(a[10], a17_4)
            + m(a[11], a16_4)
            + m(a[12], a15_4)
            + m(a[13], a14_4);
        t[10] = m(a[5], a[5])
            + m(a0_2, a[10])
            + m(a1_2, a[9])
            + m(a2_2, a[8])
            + m(a3_2, a[7])
            + m(a4_2, a[6])
            + m(a[11], a17_4)
            + m(a[12], a16_4)
            + m(a[13], a15_4)
            + m(a[14], a[14]) * 2;
        t[11] = m(a0_2, a[11])
            + m(a1_2, a[10])
            + m(a2_2, a[9])
            + m(a3_2, a[8])
            + m(a4_2, a[7])
            + m(a5_2, a[6])
            + m(a[12], a17_4)
            + m(a[13], a16_4)
            + m(a[14], a15_4);
        t[12] = m(a[6], a[6])
            + m(a0_2, a[12])
            + m(a1_2, a[11])
            + m(a2_2, a[10])
            + m(a3_2, a[9])
            + m(a4_2, a[8])
            + m(a5_2, a[7])
            + m(a[13], a17_4)
            + m(a[14], a16_4)
            + m(a[15], a[15]) * 2;
        t[13] = m(a0_2, a[13])
            + m(a1_2, a[12])
            + m(a2_2, a[11])
            + m(a3_2, a[10])
            + m(a4_2, a[9])
            + m(a5_2, a[8])
            + m(a6_2, a[7])
            + m(a[14], a17_4)
            + m(a[15], a16_4);
        t[14] = m(a[7], a[7])
            + m(a0_2, a[14])
            + m(a1_2, a[13])
            + m(a2_2, a[12])
            + m(a3_2, a[11])
            + m(a4_2, a[10])
            + m(a5_2, a[9])
            + m(a6_2, a[8])
            + m(a[15], a17_4)
            + m(a[16], a[16]) * 2;
        t[15] = m(a0_2, a[15])
            + m(a1_2, a[14])
            + m(a2_2, a[13])
            + m(a3_2, a[12])
            + m(a4_2, a[11])
            + m(a5_2, a[10])
            + m(a6_2, a[9])
            + m(a7_2, a[8])
            + m(a[16], a17_4);
        t[16] = m(a[8], a[8])
            + m(a0_2, a[16])
            + m(a1_2, a[15])
            + m(a2_2, a[14])
            + m(a3_2, a[13])
            + m(a4_2, a[12])
            + m(a5_2, a[11])
            + m(a6_2, a[10])
            + m(a7_2, a[9])
            + m(a[17], a[17]) * 2;
        t[17] = m(a0_2, a[17])
            + m(a1_2, a[16])
            + m(a2_2, a[15])
            + m(a3_2, a[14])
            + m(a4_2, a[13])
            + m(a5_2, a[12])
            + m(a6_2, a[11])
            + m(a7_2, a[10])
            + m(a8_2, a[9]);
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
        let r9_2 = rhs[9] * 2;
        let r10_2 = rhs[10] * 2;
        let r11_2 = rhs[11] * 2;
        let r12_2 = rhs[12] * 2;
        let r13_2 = rhs[13] * 2;
        let r14_2 = rhs[14] * 2;
        let r15_2 = rhs[15] * 2;
        let r16_2 = rhs[16] * 2;
        let r17_2 = rhs[17] * 2;
        let mut t = [0u64; 18];
        t[0] = m(self[0], rhs[0])
            + m(self[1], r17_2)
            + m(self[2], r16_2)
            + m(self[3], r15_2)
            + m(self[4], r14_2)
            + m(self[5], r13_2)
            + m(self[6], r12_2)
            + m(self[7], r11_2)
            + m(self[8], r10_2)
            + m(self[9], r9_2)
            + m(self[10], r8_2)
            + m(self[11], r7_2)
            + m(self[12], r6_2)
            + m(self[13], r5_2)
            + m(self[14], r4_2)
            + m(self[15], r3_2)
            + m(self[16], r2_2)
            + m(self[17], r1_2);
        t[1] = m(self[0], rhs[1])
            + m(self[1], rhs[0])
            + m(self[2], r17_2)
            + m(self[3], r16_2)
            + m(self[4], r15_2)
            + m(self[5], r14_2)
            + m(self[6], r13_2)
            + m(self[7], r12_2)
            + m(self[8], r11_2)
            + m(self[9], r10_2)
            + m(self[10], r9_2)
            + m(self[11], r8_2)
            + m(self[12], r7_2)
            + m(self[13], r6_2)
            + m(self[14], r5_2)
            + m(self[15], r4_2)
            + m(self[16], r3_2)
            + m(self[17], r2_2);
        t[2] = m(self[0], rhs[2])
            + m(self[1], rhs[1])
            + m(self[2], rhs[0])
            + m(self[3], r17_2)
            + m(self[4], r16_2)
            + m(self[5], r15_2)
            + m(self[6], r14_2)
            + m(self[7], r13_2)
            + m(self[8], r12_2)
            + m(self[9], r11_2)
            + m(self[10], r10_2)
            + m(self[11], r9_2)
            + m(self[12], r8_2)
            + m(self[13], r7_2)
            + m(self[14], r6_2)
            + m(self[15], r5_2)
            + m(self[16], r4_2)
            + m(self[17], r3_2);
        t[3] = m(self[0], rhs[3])
            + m(self[1], rhs[2])
            + m(self[2], rhs[1])
            + m(self[3], rhs[0])
            + m(self[4], r17_2)
            + m(self[5], r16_2)
            + m(self[6], r15_2)
            + m(self[7], r14_2)
            + m(self[8], r13_2)
            + m(self[9], r12_2)
            + m(self[10], r11_2)
            + m(self[11], r10_2)
            + m(self[12], r9_2)
            + m(self[13], r8_2)
            + m(self[14], r7_2)
            + m(self[15], r6_2)
            + m(self[16], r5_2)
            + m(self[17], r4_2);
        t[4] = m(self[0], rhs[4])
            + m(self[1], rhs[3])
            + m(self[2], rhs[2])
            + m(self[3], rhs[1])
            + m(self[4], rhs[0])
            + m(self[5], r17_2)
            + m(self[6], r16_2)
            + m(self[7], r15_2)
            + m(self[8], r14_2)
            + m(self[9], r13_2)
            + m(self[10], r12_2)
            + m(self[11], r11_2)
            + m(self[12], r10_2)
            + m(self[13], r9_2)
            + m(self[14], r8_2)
            + m(self[15], r7_2)
            + m(self[16], r6_2)
            + m(self[17], r5_2);
        t[5] = m(self[0], rhs[5])
            + m(self[1], rhs[4])
            + m(self[2], rhs[3])
            + m(self[3], rhs[2])
            + m(self[4], rhs[1])
            + m(self[5], rhs[0])
            + m(self[6], r17_2)
            + m(self[7], r16_2)
            + m(self[8], r15_2)
            + m(self[9], r14_2)
            + m(self[10], r13_2)
            + m(self[11], r12_2)
            + m(self[12], r11_2)
            + m(self[13], r10_2)
            + m(self[14], r9_2)
            + m(self[15], r8_2)
            + m(self[16], r7_2)
            + m(self[17], r6_2);
        t[6] = m(self[0], rhs[6])
            + m(self[1], rhs[5])
            + m(self[2], rhs[4])
            + m(self[3], rhs[3])
            + m(self[4], rhs[2])
            + m(self[5], rhs[1])
            + m(self[6], rhs[0])
            + m(self[7], r17_2)
            + m(self[8], r16_2)
            + m(self[9], r15_2)
            + m(self[10], r14_2)
            + m(self[11], r13_2)
            + m(self[12], r12_2)
            + m(self[13], r11_2)
            + m(self[14], r10_2)
            + m(self[15], r9_2)
            + m(self[16], r8_2)
            + m(self[17], r7_2);
        t[7] = m(self[0], rhs[7])
            + m(self[1], rhs[6])
            + m(self[2], rhs[5])
            + m(self[3], rhs[4])
            + m(self[4], rhs[3])
            + m(self[5], rhs[2])
            + m(self[6], rhs[1])
            + m(self[7], rhs[0])
            + m(self[8], r17_2)
            + m(self[9], r16_2)
            + m(self[10], r15_2)
            + m(self[11], r14_2)
            + m(self[12], r13_2)
            + m(self[13], r12_2)
            + m(self[14], r11_2)
            + m(self[15], r10_2)
            + m(self[16], r9_2)
            + m(self[17], r8_2);
        t[8] = m(self[0], rhs[8])
            + m(self[1], rhs[7])
            + m(self[2], rhs[6])
            + m(self[3], rhs[5])
            + m(self[4], rhs[4])
            + m(self[5], rhs[3])
            + m(self[6], rhs[2])
            + m(self[7], rhs[1])
            + m(self[8], rhs[0])
            + m(self[9], r17_2)
            + m(self[10], r16_2)
            + m(self[11], r15_2)
            + m(self[12], r14_2)
            + m(self[13], r13_2)
            + m(self[14], r12_2)
            + m(self[15], r11_2)
            + m(self[16], r10_2)
            + m(self[17], r9_2);
        t[9] = m(self[0], rhs[9])
            + m(self[1], rhs[8])
            + m(self[2], rhs[7])
            + m(self[3], rhs[6])
            + m(self[4], rhs[5])
            + m(self[5], rhs[4])
            + m(self[6], rhs[3])
            + m(self[7], rhs[2])
            + m(self[8], rhs[1])
            + m(self[9], rhs[0])
            + m(self[10], r17_2)
            + m(self[11], r16_2)
            + m(self[12], r15_2)
            + m(self[13], r14_2)
            + m(self[14], r13_2)
            + m(self[15], r12_2)
            + m(self[16], r11_2)
            + m(self[17], r10_2);
        t[10] = m(self[0], rhs[10])
            + m(self[1], rhs[9])
            + m(self[2], rhs[8])
            + m(self[3], rhs[7])
            + m(self[4], rhs[6])
            + m(self[5], rhs[5])
            + m(self[6], rhs[4])
            + m(self[7], rhs[3])
            + m(self[8], rhs[2])
            + m(self[9], rhs[1])
            + m(self[10], rhs[0])
            + m(self[11], r17_2)
            + m(self[12], r16_2)
            + m(self[13], r15_2)
            + m(self[14], r14_2)
            + m(self[15], r13_2)
            + m(self[16], r12_2)
            + m(self[17], r11_2);
        t[11] = m(self[0], rhs[11])
            + m(self[1], rhs[10])
            + m(self[2], rhs[9])
            + m(self[3], rhs[8])
            + m(self[4], rhs[7])
            + m(self[5], rhs[6])
            + m(self[6], rhs[5])
            + m(self[7], rhs[4])
            + m(self[8], rhs[3])
            + m(self[9], rhs[2])
            + m(self[10], rhs[1])
            + m(self[11], rhs[0])
            + m(self[12], r17_2)
            + m(self[13], r16_2)
            + m(self[14], r15_2)
            + m(self[15], r14_2)
            + m(self[16], r13_2)
            + m(self[17], r12_2);
        t[12] = m(self[0], rhs[12])
            + m(self[1], rhs[11])
            + m(self[2], rhs[10])
            + m(self[3], rhs[9])
            + m(self[4], rhs[8])
            + m(self[5], rhs[7])
            + m(self[6], rhs[6])
            + m(self[7], rhs[5])
            + m(self[8], rhs[4])
            + m(self[9], rhs[3])
            + m(self[10], rhs[2])
            + m(self[11], rhs[1])
            + m(self[12], rhs[0])
            + m(self[13], r17_2)
            + m(self[14], r16_2)
            + m(self[15], r15_2)
            + m(self[16], r14_2)
            + m(self[17], r13_2);
        t[13] = m(self[0], rhs[13])
            + m(self[1], rhs[12])
            + m(self[2], rhs[11])
            + m(self[3], rhs[10])
            + m(self[4], rhs[9])
            + m(self[5], rhs[8])
            + m(self[6], rhs[7])
            + m(self[7], rhs[6])
            + m(self[8], rhs[5])
            + m(self[9], rhs[4])
            + m(self[10], rhs[3])
            + m(self[11], rhs[2])
            + m(self[12], rhs[1])
            + m(self[13], rhs[0])
            + m(self[14], r17_2)
            + m(self[15], r16_2)
            + m(self[16], r15_2)
            + m(self[17], r14_2);
        t[14] = m(self[0], rhs[14])
            + m(self[1], rhs[13])
            + m(self[2], rhs[12])
            + m(self[3], rhs[11])
            + m(self[4], rhs[10])
            + m(self[5], rhs[9])
            + m(self[6], rhs[8])
            + m(self[7], rhs[7])
            + m(self[8], rhs[6])
            + m(self[9], rhs[5])
            + m(self[10], rhs[4])
            + m(self[11], rhs[3])
            + m(self[12], rhs[2])
            + m(self[13], rhs[1])
            + m(self[14], rhs[0])
            + m(self[15], r17_2)
            + m(self[16], r16_2)
            + m(self[17], r15_2);
        t[15] = m(self[0], rhs[15])
            + m(self[1], rhs[14])
            + m(self[2], rhs[13])
            + m(self[3], rhs[12])
            + m(self[4], rhs[11])
            + m(self[5], rhs[10])
            + m(self[6], rhs[9])
            + m(self[7], rhs[8])
            + m(self[8], rhs[7])
            + m(self[9], rhs[6])
            + m(self[10], rhs[5])
            + m(self[11], rhs[4])
            + m(self[12], rhs[3])
            + m(self[13], rhs[2])
            + m(self[14], rhs[1])
            + m(self[15], rhs[0])
            + m(self[16], r17_2)
            + m(self[17], r16_2);
        t[16] = m(self[0], rhs[16])
            + m(self[1], rhs[15])
            + m(self[2], rhs[14])
            + m(self[3], rhs[13])
            + m(self[4], rhs[12])
            + m(self[5], rhs[11])
            + m(self[6], rhs[10])
            + m(self[7], rhs[9])
            + m(self[8], rhs[8])
            + m(self[9], rhs[7])
            + m(self[10], rhs[6])
            + m(self[11], rhs[5])
            + m(self[12], rhs[4])
            + m(self[13], rhs[3])
            + m(self[14], rhs[2])
            + m(self[15], rhs[1])
            + m(self[16], rhs[0])
            + m(self[17], r17_2);
        t[17] = m(self[0], rhs[17])
            + m(self[1], rhs[16])
            + m(self[2], rhs[15])
            + m(self[3], rhs[14])
            + m(self[4], rhs[13])
            + m(self[5], rhs[12])
            + m(self[6], rhs[11])
            + m(self[7], rhs[10])
            + m(self[8], rhs[9])
            + m(self[9], rhs[8])
            + m(self[10], rhs[7])
            + m(self[11], rhs[6])
            + m(self[12], rhs[5])
            + m(self[13], rhs[4])
            + m(self[14], rhs[3])
            + m(self[15], rhs[2])
            + m(self[16], rhs[1])
            + m(self[17], rhs[0]);
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
        let mut result = 0u32;
        for i in 0..18 {
            result |= diff[i];
        }
        result == 0
    }

    pub(super) fn from_u32(n: u32) -> Self {
        let mut result = Self::ZERO;
        result[0] = n;
        result.reduce();
        result
    }

    pub(super) fn from_bytes(bytes: &[u8; 66]) -> Self {
        let mut padded = [0u8; 72];
        for i in 0..66 {
            padded[i] = bytes[65 - i];
        }
        let mut words = [0u32; 18];
        for (i, chunk) in padded.as_chunks::<4>().0.iter().enumerate() {
            words[i] = u32::from_le_bytes(*chunk);
        }
        let mut result = Self::ZERO;
        result[0] = words[0] & Self::MASK;
        result[1] = ((words[0] >> 29) | (words[1] << 3)) & Self::MASK;
        result[2] = ((words[1] >> 26) | (words[2] << 6)) & Self::MASK;
        result[3] = ((words[2] >> 23) | (words[3] << 9)) & Self::MASK;
        result[4] = ((words[3] >> 20) | (words[4] << 12)) & Self::MASK;
        result[5] = ((words[4] >> 17) | (words[5] << 15)) & Self::MASK;
        result[6] = ((words[5] >> 14) | (words[6] << 18)) & Self::MASK;
        result[7] = ((words[6] >> 11) | (words[7] << 21)) & Self::MASK;
        result[8] = ((words[7] >> 8) | (words[8] << 24)) & Self::MASK;
        result[9] = ((words[8] >> 5) | (words[9] << 27)) & Self::MASK;
        result[10] = (words[9] >> 2) & Self::MASK;
        result[11] = ((words[9] >> 31) | (words[10] << 1)) & Self::MASK;
        result[12] = ((words[10] >> 28) | (words[11] << 4)) & Self::MASK;
        result[13] = ((words[11] >> 25) | (words[12] << 7)) & Self::MASK;
        result[14] = ((words[12] >> 22) | (words[13] << 10)) & Self::MASK;
        result[15] = ((words[13] >> 19) | (words[14] << 13)) & Self::MASK;
        result[16] = ((words[14] >> 16) | (words[15] << 16)) & Self::MASK;
        result[17] = ((words[15] >> 13) | (words[16] << 19)) & Self::TOP_MASK;
        result
    }

    pub(super) fn to_bytes(mut self) -> [u8; 66] {
        self.canonical();
        let words: [u32; 17] = [
            self[0] | (self[1] << 29),
            (self[1] >> 3) | (self[2] << 26),
            (self[2] >> 6) | (self[3] << 23),
            (self[3] >> 9) | (self[4] << 20),
            (self[4] >> 12) | (self[5] << 17),
            (self[5] >> 15) | (self[6] << 14),
            (self[6] >> 18) | (self[7] << 11),
            (self[7] >> 21) | (self[8] << 8),
            (self[8] >> 24) | (self[9] << 5),
            (self[9] >> 27) | (self[10] << 2) | (self[11] << 31),
            (self[11] >> 1) | (self[12] << 28),
            (self[12] >> 4) | (self[13] << 25),
            (self[13] >> 7) | (self[14] << 22),
            (self[14] >> 10) | (self[15] << 19),
            (self[15] >> 13) | (self[16] << 16),
            (self[16] >> 16) | (self[17] << 13),
            self[17] >> 19,
        ];
        let mut bytes = [0u8; 72];
        for (i, word) in words.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        let mut result = [0u8; 66];
        result.copy_from_slice(&bytes[..66]);
        result.reverse();
        result
    }
}

impl FieldP521 {
    const MASK: u32 = (1 << 29) - 1;
    const TOP_MASK: u32 = (1 << 28) - 1;
    const P2: Self = Self([
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
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

    fn carry(&mut self) {
        self[1] += self[0] >> 29;
        self[2] += self[1] >> 29;
        self[3] += self[2] >> 29;
        self[4] += self[3] >> 29;
        self[5] += self[4] >> 29;
        self[6] += self[5] >> 29;
        self[7] += self[6] >> 29;
        self[8] += self[7] >> 29;
        self[9] += self[8] >> 29;
        self[10] += self[9] >> 29;
        self[11] += self[10] >> 29;
        self[12] += self[11] >> 29;
        self[13] += self[12] >> 29;
        self[14] += self[13] >> 29;
        self[15] += self[14] >> 29;
        self[16] += self[15] >> 29;
        self[17] += self[16] >> 29;
    }

    fn mask(&mut self) {
        for i in 0..17 {
            self[i] &= Self::MASK;
        }
        self[17] &= Self::TOP_MASK;
    }

    fn reduce(&mut self) {
        self.carry();
        let carry = self[17] >> 28;
        self.mask();
        self[0] += carry;
        self[1] += self[0] >> 29;
        self[2] += self[1] >> 29;
        self[0] &= Self::MASK;
        self[1] &= Self::MASK;
    }

    fn canonical(&mut self) {
        let mut reduced = *self;
        reduced[0] += 1;
        reduced.carry();
        reduced[17] = reduced[17].wrapping_sub(1 << 28);
        let borrow = reduced[17] >> 31;
        reduced.mask();
        *self = Self::select(&reduced, self, borrow as u64);
    }

    const fn reduce_wide(mut words: [u64; 18]) -> Self {
        words[1] += words[0] >> 29;
        words[2] += words[1] >> 29;
        words[3] += words[2] >> 29;
        words[4] += words[3] >> 29;
        words[5] += words[4] >> 29;
        words[6] += words[5] >> 29;
        words[7] += words[6] >> 29;
        words[8] += words[7] >> 29;
        words[9] += words[8] >> 29;
        words[10] += words[9] >> 29;
        words[11] += words[10] >> 29;
        words[12] += words[11] >> 29;
        words[13] += words[12] >> 29;
        words[14] += words[13] >> 29;
        words[15] += words[14] >> 29;
        words[16] += words[15] >> 29;
        words[17] += words[16] >> 29;
        let carry = (words[17] >> 28) as u32;
        let mut t = [
            (words[0] as u32) & Self::MASK,
            (words[1] as u32) & Self::MASK,
            (words[2] as u32) & Self::MASK,
            (words[3] as u32) & Self::MASK,
            (words[4] as u32) & Self::MASK,
            (words[5] as u32) & Self::MASK,
            (words[6] as u32) & Self::MASK,
            (words[7] as u32) & Self::MASK,
            (words[8] as u32) & Self::MASK,
            (words[9] as u32) & Self::MASK,
            (words[10] as u32) & Self::MASK,
            (words[11] as u32) & Self::MASK,
            (words[12] as u32) & Self::MASK,
            (words[13] as u32) & Self::MASK,
            (words[14] as u32) & Self::MASK,
            (words[15] as u32) & Self::MASK,
            (words[16] as u32) & Self::MASK,
            (words[17] as u32) & Self::TOP_MASK,
        ];
        t[0] += carry;
        t[1] += t[0] >> 29;
        t[2] += t[1] >> 29;
        t[0] &= Self::MASK;
        t[1] &= Self::MASK;
        Self(t)
    }
}
