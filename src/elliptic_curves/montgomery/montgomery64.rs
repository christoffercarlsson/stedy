use {
    super::{Montgomery, WideWord, Word},
    crate::{traits::MontgomeryParams, utils::unsigned_mul as m},
    core::{
        marker::PhantomData,
        ops::{Index, IndexMut},
    },
};

impl_montgomery!(5);
impl_montgomery!(7);
impl_montgomery!(9);

impl<P> Montgomery<5, P>
where
    P: MontgomeryParams<5>,
{
    pub(crate) fn montgomery_mul(self, rhs: Self) -> Self {
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
        Self::montgomery_reduce(&mut t)
    }

    pub(crate) fn montgomery_square(self) -> Self {
        let mut t = [0u128; 10];
        let d0 = m(self[0], self[0]);
        let d1 = m(self[1], self[1]);
        let d2 = m(self[2], self[2]);
        let d3 = m(self[3], self[3]);
        let d4 = m(self[4], self[4]);
        let c01 = m(self[0], self[1]) << 1;
        let c02 = m(self[0], self[2]) << 1;
        let c03 = m(self[0], self[3]) << 1;
        let c04 = m(self[0], self[4]) << 1;
        let c12 = m(self[1], self[2]) << 1;
        let c13 = m(self[1], self[3]) << 1;
        let c14 = m(self[1], self[4]) << 1;
        let c23 = m(self[2], self[3]) << 1;
        let c24 = m(self[2], self[4]) << 1;
        let c34 = m(self[3], self[4]) << 1;
        t[0] = d0;
        t[1] = c01;
        t[2] = c02 + d1;
        t[3] = c03 + c12;
        t[4] = c04 + c13 + d2;
        t[5] = c14 + c23;
        t[6] = c24 + d3;
        t[7] = c34;
        t[8] = d4;
        Self::montgomery_reduce(&mut t)
    }

    fn montgomery_reduce(t: &mut [u128; 10]) -> Self {
        Self::round(t, 0);
        Self::round(t, 1);
        Self::round(t, 2);
        Self::round(t, 3);
        Self::round(t, 4);
        t[6] += t[5] >> P::BITS;
        t[7] += t[6] >> P::BITS;
        t[8] += t[7] >> P::BITS;
        t[9] += t[8] >> P::BITS;
        let mut s = Self::from_limbs([
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
}

impl<P> Montgomery<9, P>
where
    P: MontgomeryParams<9>,
{
    fn montgomery_mul(self, rhs: Self) -> Self {
        let mut t = [0u128; 18];
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
        t[9] = m(self[1], rhs[8])
            + m(self[2], rhs[7])
            + m(self[3], rhs[6])
            + m(self[4], rhs[5])
            + m(self[5], rhs[4])
            + m(self[6], rhs[3])
            + m(self[7], rhs[2])
            + m(self[8], rhs[1]);
        t[10] = m(self[2], rhs[8])
            + m(self[3], rhs[7])
            + m(self[4], rhs[6])
            + m(self[5], rhs[5])
            + m(self[6], rhs[4])
            + m(self[7], rhs[3])
            + m(self[8], rhs[2]);
        t[11] = m(self[3], rhs[8])
            + m(self[4], rhs[7])
            + m(self[5], rhs[6])
            + m(self[6], rhs[5])
            + m(self[7], rhs[4])
            + m(self[8], rhs[3]);
        t[12] = m(self[4], rhs[8])
            + m(self[5], rhs[7])
            + m(self[6], rhs[6])
            + m(self[7], rhs[5])
            + m(self[8], rhs[4]);
        t[13] = m(self[5], rhs[8]) + m(self[6], rhs[7]) + m(self[7], rhs[6]) + m(self[8], rhs[5]);
        t[14] = m(self[6], rhs[8]) + m(self[7], rhs[7]) + m(self[8], rhs[6]);
        t[15] = m(self[7], rhs[8]) + m(self[8], rhs[7]);
        t[16] = m(self[8], rhs[8]);
        Self::montgomery_reduce(&mut t)
    }

    fn montgomery_square(self) -> Self {
        let mut t = [0u128; 18];
        let d0 = m(self[0], self[0]);
        let d1 = m(self[1], self[1]);
        let d2 = m(self[2], self[2]);
        let d3 = m(self[3], self[3]);
        let d4 = m(self[4], self[4]);
        let d5 = m(self[5], self[5]);
        let d6 = m(self[6], self[6]);
        let d7 = m(self[7], self[7]);
        let d8 = m(self[8], self[8]);
        let c01 = m(self[0], self[1]) << 1;
        let c02 = m(self[0], self[2]) << 1;
        let c03 = m(self[0], self[3]) << 1;
        let c04 = m(self[0], self[4]) << 1;
        let c05 = m(self[0], self[5]) << 1;
        let c06 = m(self[0], self[6]) << 1;
        let c07 = m(self[0], self[7]) << 1;
        let c08 = m(self[0], self[8]) << 1;
        let c12 = m(self[1], self[2]) << 1;
        let c13 = m(self[1], self[3]) << 1;
        let c14 = m(self[1], self[4]) << 1;
        let c15 = m(self[1], self[5]) << 1;
        let c16 = m(self[1], self[6]) << 1;
        let c17 = m(self[1], self[7]) << 1;
        let c18 = m(self[1], self[8]) << 1;
        let c23 = m(self[2], self[3]) << 1;
        let c24 = m(self[2], self[4]) << 1;
        let c25 = m(self[2], self[5]) << 1;
        let c26 = m(self[2], self[6]) << 1;
        let c27 = m(self[2], self[7]) << 1;
        let c28 = m(self[2], self[8]) << 1;
        let c34 = m(self[3], self[4]) << 1;
        let c35 = m(self[3], self[5]) << 1;
        let c36 = m(self[3], self[6]) << 1;
        let c37 = m(self[3], self[7]) << 1;
        let c38 = m(self[3], self[8]) << 1;
        let c45 = m(self[4], self[5]) << 1;
        let c46 = m(self[4], self[6]) << 1;
        let c47 = m(self[4], self[7]) << 1;
        let c48 = m(self[4], self[8]) << 1;
        let c56 = m(self[5], self[6]) << 1;
        let c57 = m(self[5], self[7]) << 1;
        let c58 = m(self[5], self[8]) << 1;
        let c67 = m(self[6], self[7]) << 1;
        let c68 = m(self[6], self[8]) << 1;
        let c78 = m(self[7], self[8]) << 1;
        t[0] = d0;
        t[1] = c01;
        t[2] = c02 + d1;
        t[3] = c03 + c12;
        t[4] = c04 + c13 + d2;
        t[5] = c05 + c14 + c23;
        t[6] = c06 + c15 + c24 + d3;
        t[7] = c07 + c16 + c25 + c34;
        t[8] = c08 + c17 + c26 + c35 + d4;
        t[9] = c18 + c27 + c36 + c45;
        t[10] = c28 + c37 + c46 + d5;
        t[11] = c38 + c47 + c56;
        t[12] = c48 + c57 + d6;
        t[13] = c58 + c67;
        t[14] = c68 + d7;
        t[15] = c78;
        t[16] = d8;
        Self::montgomery_reduce(&mut t)
    }

    fn montgomery_reduce(t: &mut [u128; 18]) -> Self {
        Self::round(t, 0);
        Self::round(t, 1);
        Self::round(t, 2);
        Self::round(t, 3);
        Self::round(t, 4);
        Self::round(t, 5);
        Self::round(t, 6);
        Self::round(t, 7);
        Self::round(t, 8);
        t[10] += t[9] >> P::BITS;
        t[11] += t[10] >> P::BITS;
        t[12] += t[11] >> P::BITS;
        t[13] += t[12] >> P::BITS;
        t[14] += t[13] >> P::BITS;
        t[15] += t[14] >> P::BITS;
        t[16] += t[15] >> P::BITS;
        t[17] += t[16] >> P::BITS;
        let mut s = Self::from_limbs([
            t[9] as u64,
            t[10] as u64,
            t[11] as u64,
            t[12] as u64,
            t[13] as u64,
            t[14] as u64,
            t[15] as u64,
            t[16] as u64,
            t[17] as u64,
        ]);
        s.mask();
        s.reduce();
        s
    }
}

impl<P> Montgomery<7, P>
where
    P: MontgomeryParams<7>,
{
    fn montgomery_mul(self, rhs: Self) -> Self {
        let mut t = [0u128; 14];
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
        t[7] = m(self[1], rhs[6])
            + m(self[2], rhs[5])
            + m(self[3], rhs[4])
            + m(self[4], rhs[3])
            + m(self[5], rhs[2])
            + m(self[6], rhs[1]);
        t[8] = m(self[2], rhs[6])
            + m(self[3], rhs[5])
            + m(self[4], rhs[4])
            + m(self[5], rhs[3])
            + m(self[6], rhs[2]);
        t[9] = m(self[3], rhs[6]) + m(self[4], rhs[5]) + m(self[5], rhs[4]) + m(self[6], rhs[3]);
        t[10] = m(self[4], rhs[6]) + m(self[5], rhs[5]) + m(self[6], rhs[4]);
        t[11] = m(self[5], rhs[6]) + m(self[6], rhs[5]);
        t[12] = m(self[6], rhs[6]);
        Self::montgomery_reduce(&mut t)
    }

    fn montgomery_square(self) -> Self {
        let mut t = [0u128; 14];
        let d0 = m(self[0], self[0]);
        let d1 = m(self[1], self[1]);
        let d2 = m(self[2], self[2]);
        let d3 = m(self[3], self[3]);
        let d4 = m(self[4], self[4]);
        let d5 = m(self[5], self[5]);
        let d6 = m(self[6], self[6]);
        let c01 = m(self[0], self[1]) << 1;
        let c02 = m(self[0], self[2]) << 1;
        let c03 = m(self[0], self[3]) << 1;
        let c04 = m(self[0], self[4]) << 1;
        let c05 = m(self[0], self[5]) << 1;
        let c06 = m(self[0], self[6]) << 1;
        let c12 = m(self[1], self[2]) << 1;
        let c13 = m(self[1], self[3]) << 1;
        let c14 = m(self[1], self[4]) << 1;
        let c15 = m(self[1], self[5]) << 1;
        let c16 = m(self[1], self[6]) << 1;
        let c23 = m(self[2], self[3]) << 1;
        let c24 = m(self[2], self[4]) << 1;
        let c25 = m(self[2], self[5]) << 1;
        let c26 = m(self[2], self[6]) << 1;
        let c34 = m(self[3], self[4]) << 1;
        let c35 = m(self[3], self[5]) << 1;
        let c36 = m(self[3], self[6]) << 1;
        let c45 = m(self[4], self[5]) << 1;
        let c46 = m(self[4], self[6]) << 1;
        let c56 = m(self[5], self[6]) << 1;
        t[0] = d0;
        t[1] = c01;
        t[2] = c02 + d1;
        t[3] = c03 + c12;
        t[4] = c04 + c13 + d2;
        t[5] = c05 + c14 + c23;
        t[6] = c06 + c15 + c24 + d3;
        t[7] = c16 + c25 + c34;
        t[8] = c26 + c35 + d4;
        t[9] = c36 + c45;
        t[10] = c46 + d5;
        t[11] = c56;
        t[12] = d6;
        Self::montgomery_reduce(&mut t)
    }

    fn montgomery_reduce(t: &mut [u128; 14]) -> Self {
        Self::round(t, 0);
        Self::round(t, 1);
        Self::round(t, 2);
        Self::round(t, 3);
        Self::round(t, 4);
        Self::round(t, 5);
        Self::round(t, 6);
        t[8] += t[7] >> P::BITS;
        t[9] += t[8] >> P::BITS;
        t[10] += t[9] >> P::BITS;
        t[11] += t[10] >> P::BITS;
        t[12] += t[11] >> P::BITS;
        t[13] += t[12] >> P::BITS;
        let mut s = Self::from_limbs([
            t[7] as u64,
            t[8] as u64,
            t[9] as u64,
            t[10] as u64,
            t[11] as u64,
            t[12] as u64,
            t[13] as u64,
        ]);
        s.mask();
        s.reduce();
        s
    }
}
