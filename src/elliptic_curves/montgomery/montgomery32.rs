use {
    super::{Montgomery, WideWord, Word},
    crate::{traits::MontgomeryParams, utils::unsigned_mul as m},
    core::{
        marker::PhantomData,
        ops::{Index, IndexMut},
    },
};

impl_montgomery!(10);
impl_montgomery!(14);
impl_montgomery!(18);

impl<P> Montgomery<10, P>
where
    P: MontgomeryParams<10>,
{
    pub(crate) fn montgomery_mul(self, rhs: Self) -> Self {
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
        Self::montgomery_reduce(&mut t)
    }

    pub(crate) fn montgomery_square(self) -> Self {
        let mut t = [0u64; 20];
        let d0 = m(self[0], self[0]);
        let d1 = m(self[1], self[1]);
        let d2 = m(self[2], self[2]);
        let d3 = m(self[3], self[3]);
        let d4 = m(self[4], self[4]);
        let d5 = m(self[5], self[5]);
        let d6 = m(self[6], self[6]);
        let d7 = m(self[7], self[7]);
        let d8 = m(self[8], self[8]);
        let d9 = m(self[9], self[9]);
        let c01 = m(self[0], self[1]) << 1;
        let c02 = m(self[0], self[2]) << 1;
        let c03 = m(self[0], self[3]) << 1;
        let c04 = m(self[0], self[4]) << 1;
        let c05 = m(self[0], self[5]) << 1;
        let c06 = m(self[0], self[6]) << 1;
        let c07 = m(self[0], self[7]) << 1;
        let c08 = m(self[0], self[8]) << 1;
        let c09 = m(self[0], self[9]) << 1;
        let c12 = m(self[1], self[2]) << 1;
        let c13 = m(self[1], self[3]) << 1;
        let c14 = m(self[1], self[4]) << 1;
        let c15 = m(self[1], self[5]) << 1;
        let c16 = m(self[1], self[6]) << 1;
        let c17 = m(self[1], self[7]) << 1;
        let c18 = m(self[1], self[8]) << 1;
        let c19 = m(self[1], self[9]) << 1;
        let c23 = m(self[2], self[3]) << 1;
        let c24 = m(self[2], self[4]) << 1;
        let c25 = m(self[2], self[5]) << 1;
        let c26 = m(self[2], self[6]) << 1;
        let c27 = m(self[2], self[7]) << 1;
        let c28 = m(self[2], self[8]) << 1;
        let c29 = m(self[2], self[9]) << 1;
        let c34 = m(self[3], self[4]) << 1;
        let c35 = m(self[3], self[5]) << 1;
        let c36 = m(self[3], self[6]) << 1;
        let c37 = m(self[3], self[7]) << 1;
        let c38 = m(self[3], self[8]) << 1;
        let c39 = m(self[3], self[9]) << 1;
        let c45 = m(self[4], self[5]) << 1;
        let c46 = m(self[4], self[6]) << 1;
        let c47 = m(self[4], self[7]) << 1;
        let c48 = m(self[4], self[8]) << 1;
        let c49 = m(self[4], self[9]) << 1;
        let c56 = m(self[5], self[6]) << 1;
        let c57 = m(self[5], self[7]) << 1;
        let c58 = m(self[5], self[8]) << 1;
        let c59 = m(self[5], self[9]) << 1;
        let c67 = m(self[6], self[7]) << 1;
        let c68 = m(self[6], self[8]) << 1;
        let c69 = m(self[6], self[9]) << 1;
        let c78 = m(self[7], self[8]) << 1;
        let c79 = m(self[7], self[9]) << 1;
        let c89 = m(self[8], self[9]) << 1;
        t[0] = d0;
        t[1] = c01;
        t[2] = c02 + d1;
        t[3] = c03 + c12;
        t[4] = c04 + c13 + d2;
        t[5] = c05 + c14 + c23;
        t[6] = c06 + c15 + c24 + d3;
        t[7] = c07 + c16 + c25 + c34;
        t[8] = c08 + c17 + c26 + c35 + d4;
        t[9] = c09 + c18 + c27 + c36 + c45;
        t[10] = c19 + c28 + c37 + c46 + d5;
        t[11] = c29 + c38 + c47 + c56;
        t[12] = c39 + c48 + c57 + d6;
        t[13] = c49 + c58 + c67;
        t[14] = c59 + c68 + d7;
        t[15] = c69 + c78;
        t[16] = c79 + d8;
        t[17] = c89;
        t[18] = d9;
        Self::montgomery_reduce(&mut t)
    }

    fn montgomery_reduce(t: &mut [u64; 20]) -> Self {
        Self::round(t, 0);
        Self::round(t, 1);
        Self::round(t, 2);
        Self::round(t, 3);
        Self::round(t, 4);
        Self::round(t, 5);
        Self::round(t, 6);
        Self::round(t, 7);
        Self::round(t, 8);
        Self::round(t, 9);
        t[11] += t[10] >> P::BITS;
        t[12] += t[11] >> P::BITS;
        t[13] += t[12] >> P::BITS;
        t[14] += t[13] >> P::BITS;
        t[15] += t[14] >> P::BITS;
        t[16] += t[15] >> P::BITS;
        t[17] += t[16] >> P::BITS;
        t[18] += t[17] >> P::BITS;
        t[19] += t[18] >> P::BITS;
        let mut s = Self::from_limbs([
            t[10], t[11], t[12], t[13], t[14], t[15], t[16], t[17], t[18], t[19],
        ]);
        s.mask();
        s.reduce();
        s
    }
}

impl<P> Montgomery<18, P>
where
    P: MontgomeryParams<18>,
{
    pub(crate) fn montgomery_mul(self, rhs: Self) -> Self {
        let mut t = [0u64; 36];
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
            + m(self[10], rhs[0]);
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
            + m(self[11], rhs[0]);
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
            + m(self[12], rhs[0]);
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
            + m(self[13], rhs[0]);
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
            + m(self[14], rhs[0]);
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
            + m(self[15], rhs[0]);
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
            + m(self[16], rhs[0]);
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
        t[18] = m(self[1], rhs[17])
            + m(self[2], rhs[16])
            + m(self[3], rhs[15])
            + m(self[4], rhs[14])
            + m(self[5], rhs[13])
            + m(self[6], rhs[12])
            + m(self[7], rhs[11])
            + m(self[8], rhs[10])
            + m(self[9], rhs[9])
            + m(self[10], rhs[8])
            + m(self[11], rhs[7])
            + m(self[12], rhs[6])
            + m(self[13], rhs[5])
            + m(self[14], rhs[4])
            + m(self[15], rhs[3])
            + m(self[16], rhs[2])
            + m(self[17], rhs[1]);
        t[19] = m(self[2], rhs[17])
            + m(self[3], rhs[16])
            + m(self[4], rhs[15])
            + m(self[5], rhs[14])
            + m(self[6], rhs[13])
            + m(self[7], rhs[12])
            + m(self[8], rhs[11])
            + m(self[9], rhs[10])
            + m(self[10], rhs[9])
            + m(self[11], rhs[8])
            + m(self[12], rhs[7])
            + m(self[13], rhs[6])
            + m(self[14], rhs[5])
            + m(self[15], rhs[4])
            + m(self[16], rhs[3])
            + m(self[17], rhs[2]);
        t[20] = m(self[3], rhs[17])
            + m(self[4], rhs[16])
            + m(self[5], rhs[15])
            + m(self[6], rhs[14])
            + m(self[7], rhs[13])
            + m(self[8], rhs[12])
            + m(self[9], rhs[11])
            + m(self[10], rhs[10])
            + m(self[11], rhs[9])
            + m(self[12], rhs[8])
            + m(self[13], rhs[7])
            + m(self[14], rhs[6])
            + m(self[15], rhs[5])
            + m(self[16], rhs[4])
            + m(self[17], rhs[3]);
        t[21] = m(self[4], rhs[17])
            + m(self[5], rhs[16])
            + m(self[6], rhs[15])
            + m(self[7], rhs[14])
            + m(self[8], rhs[13])
            + m(self[9], rhs[12])
            + m(self[10], rhs[11])
            + m(self[11], rhs[10])
            + m(self[12], rhs[9])
            + m(self[13], rhs[8])
            + m(self[14], rhs[7])
            + m(self[15], rhs[6])
            + m(self[16], rhs[5])
            + m(self[17], rhs[4]);
        t[22] = m(self[5], rhs[17])
            + m(self[6], rhs[16])
            + m(self[7], rhs[15])
            + m(self[8], rhs[14])
            + m(self[9], rhs[13])
            + m(self[10], rhs[12])
            + m(self[11], rhs[11])
            + m(self[12], rhs[10])
            + m(self[13], rhs[9])
            + m(self[14], rhs[8])
            + m(self[15], rhs[7])
            + m(self[16], rhs[6])
            + m(self[17], rhs[5]);
        t[23] = m(self[6], rhs[17])
            + m(self[7], rhs[16])
            + m(self[8], rhs[15])
            + m(self[9], rhs[14])
            + m(self[10], rhs[13])
            + m(self[11], rhs[12])
            + m(self[12], rhs[11])
            + m(self[13], rhs[10])
            + m(self[14], rhs[9])
            + m(self[15], rhs[8])
            + m(self[16], rhs[7])
            + m(self[17], rhs[6]);
        t[24] = m(self[7], rhs[17])
            + m(self[8], rhs[16])
            + m(self[9], rhs[15])
            + m(self[10], rhs[14])
            + m(self[11], rhs[13])
            + m(self[12], rhs[12])
            + m(self[13], rhs[11])
            + m(self[14], rhs[10])
            + m(self[15], rhs[9])
            + m(self[16], rhs[8])
            + m(self[17], rhs[7]);
        t[25] = m(self[8], rhs[17])
            + m(self[9], rhs[16])
            + m(self[10], rhs[15])
            + m(self[11], rhs[14])
            + m(self[12], rhs[13])
            + m(self[13], rhs[12])
            + m(self[14], rhs[11])
            + m(self[15], rhs[10])
            + m(self[16], rhs[9])
            + m(self[17], rhs[8]);
        t[26] = m(self[9], rhs[17])
            + m(self[10], rhs[16])
            + m(self[11], rhs[15])
            + m(self[12], rhs[14])
            + m(self[13], rhs[13])
            + m(self[14], rhs[12])
            + m(self[15], rhs[11])
            + m(self[16], rhs[10])
            + m(self[17], rhs[9]);
        t[27] = m(self[10], rhs[17])
            + m(self[11], rhs[16])
            + m(self[12], rhs[15])
            + m(self[13], rhs[14])
            + m(self[14], rhs[13])
            + m(self[15], rhs[12])
            + m(self[16], rhs[11])
            + m(self[17], rhs[10]);
        t[28] = m(self[11], rhs[17])
            + m(self[12], rhs[16])
            + m(self[13], rhs[15])
            + m(self[14], rhs[14])
            + m(self[15], rhs[13])
            + m(self[16], rhs[12])
            + m(self[17], rhs[11]);
        t[29] = m(self[12], rhs[17])
            + m(self[13], rhs[16])
            + m(self[14], rhs[15])
            + m(self[15], rhs[14])
            + m(self[16], rhs[13])
            + m(self[17], rhs[12]);
        t[30] = m(self[13], rhs[17])
            + m(self[14], rhs[16])
            + m(self[15], rhs[15])
            + m(self[16], rhs[14])
            + m(self[17], rhs[13]);
        t[31] = m(self[14], rhs[17])
            + m(self[15], rhs[16])
            + m(self[16], rhs[15])
            + m(self[17], rhs[14]);
        t[32] = m(self[15], rhs[17]) + m(self[16], rhs[16]) + m(self[17], rhs[15]);
        t[33] = m(self[16], rhs[17]) + m(self[17], rhs[16]);
        t[34] = m(self[17], rhs[17]);
        Self::montgomery_reduce(&mut t)
    }

    pub(crate) fn montgomery_square(self) -> Self {
        let mut t = [0u64; 36];
        let d0 = m(self[0], self[0]);
        let d1 = m(self[1], self[1]);
        let d2 = m(self[2], self[2]);
        let d3 = m(self[3], self[3]);
        let d4 = m(self[4], self[4]);
        let d5 = m(self[5], self[5]);
        let d6 = m(self[6], self[6]);
        let d7 = m(self[7], self[7]);
        let d8 = m(self[8], self[8]);
        let d9 = m(self[9], self[9]);
        let d10 = m(self[10], self[10]);
        let d11 = m(self[11], self[11]);
        let d12 = m(self[12], self[12]);
        let d13 = m(self[13], self[13]);
        let d14 = m(self[14], self[14]);
        let d15 = m(self[15], self[15]);
        let d16 = m(self[16], self[16]);
        let d17 = m(self[17], self[17]);
        let c01 = m(self[0], self[1]) << 1;
        let c02 = m(self[0], self[2]) << 1;
        let c03 = m(self[0], self[3]) << 1;
        let c04 = m(self[0], self[4]) << 1;
        let c05 = m(self[0], self[5]) << 1;
        let c06 = m(self[0], self[6]) << 1;
        let c07 = m(self[0], self[7]) << 1;
        let c08 = m(self[0], self[8]) << 1;
        let c09 = m(self[0], self[9]) << 1;
        let c0a = m(self[0], self[10]) << 1;
        let c0b = m(self[0], self[11]) << 1;
        let c0c = m(self[0], self[12]) << 1;
        let c0d = m(self[0], self[13]) << 1;
        let c0e = m(self[0], self[14]) << 1;
        let c0f = m(self[0], self[15]) << 1;
        let c0g = m(self[0], self[16]) << 1;
        let c0h = m(self[0], self[17]) << 1;
        let c12 = m(self[1], self[2]) << 1;
        let c13 = m(self[1], self[3]) << 1;
        let c14 = m(self[1], self[4]) << 1;
        let c15 = m(self[1], self[5]) << 1;
        let c16 = m(self[1], self[6]) << 1;
        let c17 = m(self[1], self[7]) << 1;
        let c18 = m(self[1], self[8]) << 1;
        let c19 = m(self[1], self[9]) << 1;
        let c1a = m(self[1], self[10]) << 1;
        let c1b = m(self[1], self[11]) << 1;
        let c1c = m(self[1], self[12]) << 1;
        let c1d = m(self[1], self[13]) << 1;
        let c1e = m(self[1], self[14]) << 1;
        let c1f = m(self[1], self[15]) << 1;
        let c1g = m(self[1], self[16]) << 1;
        let c1h = m(self[1], self[17]) << 1;
        let c23 = m(self[2], self[3]) << 1;
        let c24 = m(self[2], self[4]) << 1;
        let c25 = m(self[2], self[5]) << 1;
        let c26 = m(self[2], self[6]) << 1;
        let c27 = m(self[2], self[7]) << 1;
        let c28 = m(self[2], self[8]) << 1;
        let c29 = m(self[2], self[9]) << 1;
        let c2a = m(self[2], self[10]) << 1;
        let c2b = m(self[2], self[11]) << 1;
        let c2c = m(self[2], self[12]) << 1;
        let c2d = m(self[2], self[13]) << 1;
        let c2e = m(self[2], self[14]) << 1;
        let c2f = m(self[2], self[15]) << 1;
        let c2g = m(self[2], self[16]) << 1;
        let c2h = m(self[2], self[17]) << 1;
        let c34 = m(self[3], self[4]) << 1;
        let c35 = m(self[3], self[5]) << 1;
        let c36 = m(self[3], self[6]) << 1;
        let c37 = m(self[3], self[7]) << 1;
        let c38 = m(self[3], self[8]) << 1;
        let c39 = m(self[3], self[9]) << 1;
        let c3a = m(self[3], self[10]) << 1;
        let c3b = m(self[3], self[11]) << 1;
        let c3c = m(self[3], self[12]) << 1;
        let c3d = m(self[3], self[13]) << 1;
        let c3e = m(self[3], self[14]) << 1;
        let c3f = m(self[3], self[15]) << 1;
        let c3g = m(self[3], self[16]) << 1;
        let c3h = m(self[3], self[17]) << 1;
        let c45 = m(self[4], self[5]) << 1;
        let c46 = m(self[4], self[6]) << 1;
        let c47 = m(self[4], self[7]) << 1;
        let c48 = m(self[4], self[8]) << 1;
        let c49 = m(self[4], self[9]) << 1;
        let c4a = m(self[4], self[10]) << 1;
        let c4b = m(self[4], self[11]) << 1;
        let c4c = m(self[4], self[12]) << 1;
        let c4d = m(self[4], self[13]) << 1;
        let c4e = m(self[4], self[14]) << 1;
        let c4f = m(self[4], self[15]) << 1;
        let c4g = m(self[4], self[16]) << 1;
        let c4h = m(self[4], self[17]) << 1;
        let c56 = m(self[5], self[6]) << 1;
        let c57 = m(self[5], self[7]) << 1;
        let c58 = m(self[5], self[8]) << 1;
        let c59 = m(self[5], self[9]) << 1;
        let c5a = m(self[5], self[10]) << 1;
        let c5b = m(self[5], self[11]) << 1;
        let c5c = m(self[5], self[12]) << 1;
        let c5d = m(self[5], self[13]) << 1;
        let c5e = m(self[5], self[14]) << 1;
        let c5f = m(self[5], self[15]) << 1;
        let c5g = m(self[5], self[16]) << 1;
        let c5h = m(self[5], self[17]) << 1;
        let c67 = m(self[6], self[7]) << 1;
        let c68 = m(self[6], self[8]) << 1;
        let c69 = m(self[6], self[9]) << 1;
        let c6a = m(self[6], self[10]) << 1;
        let c6b = m(self[6], self[11]) << 1;
        let c6c = m(self[6], self[12]) << 1;
        let c6d = m(self[6], self[13]) << 1;
        let c6e = m(self[6], self[14]) << 1;
        let c6f = m(self[6], self[15]) << 1;
        let c6g = m(self[6], self[16]) << 1;
        let c6h = m(self[6], self[17]) << 1;
        let c78 = m(self[7], self[8]) << 1;
        let c79 = m(self[7], self[9]) << 1;
        let c7a = m(self[7], self[10]) << 1;
        let c7b = m(self[7], self[11]) << 1;
        let c7c = m(self[7], self[12]) << 1;
        let c7d = m(self[7], self[13]) << 1;
        let c7e = m(self[7], self[14]) << 1;
        let c7f = m(self[7], self[15]) << 1;
        let c7g = m(self[7], self[16]) << 1;
        let c7h = m(self[7], self[17]) << 1;
        let c89 = m(self[8], self[9]) << 1;
        let c8a = m(self[8], self[10]) << 1;
        let c8b = m(self[8], self[11]) << 1;
        let c8c = m(self[8], self[12]) << 1;
        let c8d = m(self[8], self[13]) << 1;
        let c8e = m(self[8], self[14]) << 1;
        let c8f = m(self[8], self[15]) << 1;
        let c8g = m(self[8], self[16]) << 1;
        let c8h = m(self[8], self[17]) << 1;
        let c9a = m(self[9], self[10]) << 1;
        let c9b = m(self[9], self[11]) << 1;
        let c9c = m(self[9], self[12]) << 1;
        let c9d = m(self[9], self[13]) << 1;
        let c9e = m(self[9], self[14]) << 1;
        let c9f = m(self[9], self[15]) << 1;
        let c9g = m(self[9], self[16]) << 1;
        let c9h = m(self[9], self[17]) << 1;
        let cab = m(self[10], self[11]) << 1;
        let cac = m(self[10], self[12]) << 1;
        let cad = m(self[10], self[13]) << 1;
        let cae = m(self[10], self[14]) << 1;
        let caf = m(self[10], self[15]) << 1;
        let cag = m(self[10], self[16]) << 1;
        let cah = m(self[10], self[17]) << 1;
        let cbc = m(self[11], self[12]) << 1;
        let cbd = m(self[11], self[13]) << 1;
        let cbe = m(self[11], self[14]) << 1;
        let cbf = m(self[11], self[15]) << 1;
        let cbg = m(self[11], self[16]) << 1;
        let cbh = m(self[11], self[17]) << 1;
        let ccd = m(self[12], self[13]) << 1;
        let cce = m(self[12], self[14]) << 1;
        let ccf = m(self[12], self[15]) << 1;
        let ccg = m(self[12], self[16]) << 1;
        let cch = m(self[12], self[17]) << 1;
        let cde = m(self[13], self[14]) << 1;
        let cdf = m(self[13], self[15]) << 1;
        let cdg = m(self[13], self[16]) << 1;
        let cdh = m(self[13], self[17]) << 1;
        let cef = m(self[14], self[15]) << 1;
        let ceg = m(self[14], self[16]) << 1;
        let ceh = m(self[14], self[17]) << 1;
        let cfg_ = m(self[15], self[16]) << 1;
        let cfh = m(self[15], self[17]) << 1;
        let cgh = m(self[16], self[17]) << 1;
        t[0] = d0;
        t[1] = c01;
        t[2] = c02 + d1;
        t[3] = c03 + c12;
        t[4] = c04 + c13 + d2;
        t[5] = c05 + c14 + c23;
        t[6] = c06 + c15 + c24 + d3;
        t[7] = c07 + c16 + c25 + c34;
        t[8] = c08 + c17 + c26 + c35 + d4;
        t[9] = c09 + c18 + c27 + c36 + c45;
        t[10] = c0a + c19 + c28 + c37 + c46 + d5;
        t[11] = c0b + c1a + c29 + c38 + c47 + c56;
        t[12] = c0c + c1b + c2a + c39 + c48 + c57 + d6;
        t[13] = c0d + c1c + c2b + c3a + c49 + c58 + c67;
        t[14] = c0e + c1d + c2c + c3b + c4a + c59 + c68 + d7;
        t[15] = c0f + c1e + c2d + c3c + c4b + c5a + c69 + c78;
        t[16] = c0g + c1f + c2e + c3d + c4c + c5b + c6a + c79 + d8;
        t[17] = c0h + c1g + c2f + c3e + c4d + c5c + c6b + c7a + c89;
        t[18] = c1h + c2g + c3f + c4e + c5d + c6c + c7b + c8a + d9;
        t[19] = c2h + c3g + c4f + c5e + c6d + c7c + c8b + c9a;
        t[20] = c3h + c4g + c5f + c6e + c7d + c8c + c9b + d10;
        t[21] = c4h + c5g + c6f + c7e + c8d + c9c + cab;
        t[22] = c5h + c6g + c7f + c8e + c9d + cac + d11;
        t[23] = c6h + c7g + c8f + c9e + cad + cbc;
        t[24] = c7h + c8g + c9f + cae + cbd + d12;
        t[25] = c8h + c9g + caf + cbe + ccd;
        t[26] = c9h + cag + cbf + cce + d13;
        t[27] = cah + cbg + ccf + cde;
        t[28] = cbh + ccg + cdf + d14;
        t[29] = cch + cdg + cef;
        t[30] = cdh + ceg + d15;
        t[31] = ceh + cfg_;
        t[32] = cfh + d16;
        t[33] = cgh;
        t[34] = d17;
        Self::montgomery_reduce(&mut t)
    }

    fn montgomery_reduce(t: &mut [u64; 36]) -> Self {
        Self::round(t, 0);
        Self::round(t, 1);
        Self::round(t, 2);
        Self::round(t, 3);
        Self::round(t, 4);
        Self::round(t, 5);
        Self::round(t, 6);
        Self::round(t, 7);
        Self::round(t, 8);
        Self::round(t, 9);
        Self::round(t, 10);
        Self::round(t, 11);
        Self::round(t, 12);
        Self::round(t, 13);
        Self::round(t, 14);
        Self::round(t, 15);
        Self::round(t, 16);
        Self::round(t, 17);
        t[19] += t[18] >> P::BITS;
        t[20] += t[19] >> P::BITS;
        t[21] += t[20] >> P::BITS;
        t[22] += t[21] >> P::BITS;
        t[23] += t[22] >> P::BITS;
        t[24] += t[23] >> P::BITS;
        t[25] += t[24] >> P::BITS;
        t[26] += t[25] >> P::BITS;
        t[27] += t[26] >> P::BITS;
        t[28] += t[27] >> P::BITS;
        t[29] += t[28] >> P::BITS;
        t[30] += t[29] >> P::BITS;
        t[31] += t[30] >> P::BITS;
        t[32] += t[31] >> P::BITS;
        t[33] += t[32] >> P::BITS;
        t[34] += t[33] >> P::BITS;
        t[35] += t[34] >> P::BITS;
        let mut s = Self::from_limbs([
            t[18], t[19], t[20], t[21], t[22], t[23], t[24], t[25], t[26], t[27], t[28], t[29],
            t[30], t[31], t[32], t[33], t[34], t[35],
        ]);
        s.mask();
        s.reduce();
        s
    }
}

impl<P> Montgomery<14, P>
where
    P: MontgomeryParams<14>,
{
    fn montgomery_mul(self, rhs: Self) -> Self {
        let mut t = [0u64; 28];
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
            + m(self[10], rhs[0]);
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
            + m(self[11], rhs[0]);
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
            + m(self[12], rhs[0]);
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
            + m(self[13], rhs[0]);
        t[14] = m(self[1], rhs[13])
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
            + m(self[13], rhs[1]);
        t[15] = m(self[2], rhs[13])
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
            + m(self[13], rhs[2]);
        t[16] = m(self[3], rhs[13])
            + m(self[4], rhs[12])
            + m(self[5], rhs[11])
            + m(self[6], rhs[10])
            + m(self[7], rhs[9])
            + m(self[8], rhs[8])
            + m(self[9], rhs[7])
            + m(self[10], rhs[6])
            + m(self[11], rhs[5])
            + m(self[12], rhs[4])
            + m(self[13], rhs[3]);
        t[17] = m(self[4], rhs[13])
            + m(self[5], rhs[12])
            + m(self[6], rhs[11])
            + m(self[7], rhs[10])
            + m(self[8], rhs[9])
            + m(self[9], rhs[8])
            + m(self[10], rhs[7])
            + m(self[11], rhs[6])
            + m(self[12], rhs[5])
            + m(self[13], rhs[4]);
        t[18] = m(self[5], rhs[13])
            + m(self[6], rhs[12])
            + m(self[7], rhs[11])
            + m(self[8], rhs[10])
            + m(self[9], rhs[9])
            + m(self[10], rhs[8])
            + m(self[11], rhs[7])
            + m(self[12], rhs[6])
            + m(self[13], rhs[5]);
        t[19] = m(self[6], rhs[13])
            + m(self[7], rhs[12])
            + m(self[8], rhs[11])
            + m(self[9], rhs[10])
            + m(self[10], rhs[9])
            + m(self[11], rhs[8])
            + m(self[12], rhs[7])
            + m(self[13], rhs[6]);
        t[20] = m(self[7], rhs[13])
            + m(self[8], rhs[12])
            + m(self[9], rhs[11])
            + m(self[10], rhs[10])
            + m(self[11], rhs[9])
            + m(self[12], rhs[8])
            + m(self[13], rhs[7]);
        t[21] = m(self[8], rhs[13])
            + m(self[9], rhs[12])
            + m(self[10], rhs[11])
            + m(self[11], rhs[10])
            + m(self[12], rhs[9])
            + m(self[13], rhs[8]);
        t[22] = m(self[9], rhs[13])
            + m(self[10], rhs[12])
            + m(self[11], rhs[11])
            + m(self[12], rhs[10])
            + m(self[13], rhs[9]);
        t[23] = m(self[10], rhs[13])
            + m(self[11], rhs[12])
            + m(self[12], rhs[11])
            + m(self[13], rhs[10]);
        t[24] = m(self[11], rhs[13]) + m(self[12], rhs[12]) + m(self[13], rhs[11]);
        t[25] = m(self[12], rhs[13]) + m(self[13], rhs[12]);
        t[26] = m(self[13], rhs[13]);
        Self::montgomery_reduce(&mut t)
    }

    fn montgomery_square(self) -> Self {
        let mut t = [0u64; 28];
        let d0 = m(self[0], self[0]);
        let d1 = m(self[1], self[1]);
        let d2 = m(self[2], self[2]);
        let d3 = m(self[3], self[3]);
        let d4 = m(self[4], self[4]);
        let d5 = m(self[5], self[5]);
        let d6 = m(self[6], self[6]);
        let d7 = m(self[7], self[7]);
        let d8 = m(self[8], self[8]);
        let d9 = m(self[9], self[9]);
        let d10 = m(self[10], self[10]);
        let d11 = m(self[11], self[11]);
        let d12 = m(self[12], self[12]);
        let d13 = m(self[13], self[13]);
        let c01 = m(self[0], self[1]) << 1;
        let c02 = m(self[0], self[2]) << 1;
        let c03 = m(self[0], self[3]) << 1;
        let c04 = m(self[0], self[4]) << 1;
        let c05 = m(self[0], self[5]) << 1;
        let c06 = m(self[0], self[6]) << 1;
        let c07 = m(self[0], self[7]) << 1;
        let c08 = m(self[0], self[8]) << 1;
        let c09 = m(self[0], self[9]) << 1;
        let c010 = m(self[0], self[10]) << 1;
        let c011 = m(self[0], self[11]) << 1;
        let c012 = m(self[0], self[12]) << 1;
        let c013 = m(self[0], self[13]) << 1;
        let c12 = m(self[1], self[2]) << 1;
        let c13 = m(self[1], self[3]) << 1;
        let c14 = m(self[1], self[4]) << 1;
        let c15 = m(self[1], self[5]) << 1;
        let c16 = m(self[1], self[6]) << 1;
        let c17 = m(self[1], self[7]) << 1;
        let c18 = m(self[1], self[8]) << 1;
        let c19 = m(self[1], self[9]) << 1;
        let c110 = m(self[1], self[10]) << 1;
        let c111 = m(self[1], self[11]) << 1;
        let c112 = m(self[1], self[12]) << 1;
        let c113 = m(self[1], self[13]) << 1;
        let c23 = m(self[2], self[3]) << 1;
        let c24 = m(self[2], self[4]) << 1;
        let c25 = m(self[2], self[5]) << 1;
        let c26 = m(self[2], self[6]) << 1;
        let c27 = m(self[2], self[7]) << 1;
        let c28 = m(self[2], self[8]) << 1;
        let c29 = m(self[2], self[9]) << 1;
        let c210 = m(self[2], self[10]) << 1;
        let c211 = m(self[2], self[11]) << 1;
        let c212 = m(self[2], self[12]) << 1;
        let c213 = m(self[2], self[13]) << 1;
        let c34 = m(self[3], self[4]) << 1;
        let c35 = m(self[3], self[5]) << 1;
        let c36 = m(self[3], self[6]) << 1;
        let c37 = m(self[3], self[7]) << 1;
        let c38 = m(self[3], self[8]) << 1;
        let c39 = m(self[3], self[9]) << 1;
        let c310 = m(self[3], self[10]) << 1;
        let c311 = m(self[3], self[11]) << 1;
        let c312 = m(self[3], self[12]) << 1;
        let c313 = m(self[3], self[13]) << 1;
        let c45 = m(self[4], self[5]) << 1;
        let c46 = m(self[4], self[6]) << 1;
        let c47 = m(self[4], self[7]) << 1;
        let c48 = m(self[4], self[8]) << 1;
        let c49 = m(self[4], self[9]) << 1;
        let c410 = m(self[4], self[10]) << 1;
        let c411 = m(self[4], self[11]) << 1;
        let c412 = m(self[4], self[12]) << 1;
        let c413 = m(self[4], self[13]) << 1;
        let c56 = m(self[5], self[6]) << 1;
        let c57 = m(self[5], self[7]) << 1;
        let c58 = m(self[5], self[8]) << 1;
        let c59 = m(self[5], self[9]) << 1;
        let c510 = m(self[5], self[10]) << 1;
        let c511 = m(self[5], self[11]) << 1;
        let c512 = m(self[5], self[12]) << 1;
        let c513 = m(self[5], self[13]) << 1;
        let c67 = m(self[6], self[7]) << 1;
        let c68 = m(self[6], self[8]) << 1;
        let c69 = m(self[6], self[9]) << 1;
        let c610 = m(self[6], self[10]) << 1;
        let c611 = m(self[6], self[11]) << 1;
        let c612 = m(self[6], self[12]) << 1;
        let c613 = m(self[6], self[13]) << 1;
        let c78 = m(self[7], self[8]) << 1;
        let c79 = m(self[7], self[9]) << 1;
        let c710 = m(self[7], self[10]) << 1;
        let c711 = m(self[7], self[11]) << 1;
        let c712 = m(self[7], self[12]) << 1;
        let c713 = m(self[7], self[13]) << 1;
        let c89 = m(self[8], self[9]) << 1;
        let c810 = m(self[8], self[10]) << 1;
        let c811 = m(self[8], self[11]) << 1;
        let c812 = m(self[8], self[12]) << 1;
        let c813 = m(self[8], self[13]) << 1;
        let c910 = m(self[9], self[10]) << 1;
        let c911 = m(self[9], self[11]) << 1;
        let c912 = m(self[9], self[12]) << 1;
        let c913 = m(self[9], self[13]) << 1;
        let c1011 = m(self[10], self[11]) << 1;
        let c1012 = m(self[10], self[12]) << 1;
        let c1013 = m(self[10], self[13]) << 1;
        let c1112 = m(self[11], self[12]) << 1;
        let c1113 = m(self[11], self[13]) << 1;
        let c1213 = m(self[12], self[13]) << 1;
        t[0] = d0;
        t[1] = c01;
        t[2] = c02 + d1;
        t[3] = c03 + c12;
        t[4] = c04 + c13 + d2;
        t[5] = c05 + c14 + c23;
        t[6] = c06 + c15 + c24 + d3;
        t[7] = c07 + c16 + c25 + c34;
        t[8] = c08 + c17 + c26 + c35 + d4;
        t[9] = c09 + c18 + c27 + c36 + c45;
        t[10] = c010 + c19 + c28 + c37 + c46 + d5;
        t[11] = c011 + c110 + c29 + c38 + c47 + c56;
        t[12] = c012 + c111 + c210 + c39 + c48 + c57 + d6;
        t[13] = c013 + c112 + c211 + c310 + c49 + c58 + c67;
        t[14] = c113 + c212 + c311 + c410 + c59 + c68 + d7;
        t[15] = c213 + c312 + c411 + c510 + c69 + c78;
        t[16] = c313 + c412 + c511 + c610 + c79 + d8;
        t[17] = c413 + c512 + c611 + c710 + c89;
        t[18] = c513 + c612 + c711 + c810 + d9;
        t[19] = c613 + c712 + c811 + c910;
        t[20] = c713 + c812 + c911 + d10;
        t[21] = c813 + c912 + c1011;
        t[22] = c913 + c1012 + d11;
        t[23] = c1013 + c1112;
        t[24] = c1113 + d12;
        t[25] = c1213;
        t[26] = d13;
        Self::montgomery_reduce(&mut t)
    }

    fn montgomery_reduce(t: &mut [u64; 28]) -> Self {
        Self::round(t, 0);
        Self::round(t, 1);
        Self::round(t, 2);
        Self::round(t, 3);
        Self::round(t, 4);
        Self::round(t, 5);
        Self::round(t, 6);
        Self::round(t, 7);
        Self::round(t, 8);
        Self::round(t, 9);
        Self::round(t, 10);
        Self::round(t, 11);
        Self::round(t, 12);
        Self::round(t, 13);
        t[15] += t[14] >> P::BITS;
        t[16] += t[15] >> P::BITS;
        t[17] += t[16] >> P::BITS;
        t[18] += t[17] >> P::BITS;
        t[19] += t[18] >> P::BITS;
        t[20] += t[19] >> P::BITS;
        t[21] += t[20] >> P::BITS;
        t[22] += t[21] >> P::BITS;
        t[23] += t[22] >> P::BITS;
        t[24] += t[23] >> P::BITS;
        t[25] += t[24] >> P::BITS;
        t[26] += t[25] >> P::BITS;
        t[27] += t[26] >> P::BITS;
        let mut s = Self::from_limbs([
            t[14], t[15], t[16], t[17], t[18], t[19], t[20], t[21], t[22], t[23], t[24], t[25],
            t[26], t[27],
        ]);
        s.mask();
        s.reduce();
        s
    }
}
