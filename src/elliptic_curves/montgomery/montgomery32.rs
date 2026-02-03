use {
    crate::{traits::MontgomeryParams, utils::unsigned_mul as m},
    core::{
        marker::PhantomData,
        ops::{Index, IndexMut},
    },
};

#[derive(Clone, Copy)]
pub struct Montgomery<const LIMBS: usize, P>([u32; LIMBS], PhantomData<P>)
where
    P: MontgomeryParams<LIMBS>;

impl<const LIMBS: usize, P> Index<usize> for Montgomery<LIMBS, P>
where
    P: MontgomeryParams<LIMBS>,
{
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<const LIMBS: usize, P> IndexMut<usize> for Montgomery<LIMBS, P>
where
    P: MontgomeryParams<LIMBS>,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<const LIMBS: usize, P> Montgomery<LIMBS, P>
where
    P: MontgomeryParams<LIMBS>,
{
    pub(crate) const R: Self = Self::new(P::R);
    pub(crate) const R2: Self = Self::new(P::R2);
    pub(crate) const MASK: u32 = Self::MASKS[0];
    pub(crate) const TOP_MASK: u32 = Self::MASKS[LIMBS - 1];
    pub(crate) const ZERO: Self = Self::new([0; LIMBS]);

    pub(crate) fn swap(a: &mut Self, b: &mut Self, condition: u64) {
        let mask = ((condition != 0) as u32).wrapping_neg();
        for i in 0..LIMBS {
            let t = mask & (a[i] ^ b[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    pub(crate) fn is_zero(&self) -> bool {
        let mut result = 0;
        for i in 0..LIMBS {
            result |= self[i];
        }
        result == 0
    }

    pub(crate) fn add(self, rhs: Self) -> Self {
        let mut result = Self::ZERO;
        for i in 0..LIMBS {
            result[i] = self[i] + rhs[i];
        }
        result.carry();
        result.mask();
        result.reduce();
        result
    }

    pub(crate) fn neg(self) -> Self {
        let mut diff = Self::ZERO;
        let mut borrow = 0u32;
        for i in 0..LIMBS {
            let (d1, b1) = (P::MOD[i] as u32).overflowing_sub(self[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            diff[i] = d2 & Self::MASKS[i];
            borrow = (b1 | b2) as u32;
        }
        Self::select(&diff, &Self::ZERO, self.is_zero() as u64)
    }
}

impl<const LIMBS: usize, P> Montgomery<LIMBS, P>
where
    P: MontgomeryParams<LIMBS>,
{
    const BITS: u32 = P::BITS;
    const MASKS: [u32; LIMBS] = {
        let mut masks = [0; LIMBS];
        let mut i = 0;
        while i < LIMBS - 1 {
            masks[i] = (1 << P::BITS) - 1;
            i += 1;
        }
        masks[LIMBS - 1] = (1 << P::TOP_BITS) - 1;
        masks
    };

    const fn new(limbs: [u64; LIMBS]) -> Self {
        let mut t = [0u32; LIMBS];
        let mut i = 0;
        while i < LIMBS {
            t[i] = limbs[i] as u32;
            i += 1;
        }
        Self(t, PhantomData::<P>)
    }

    fn carry(&mut self) {
        for i in 0..(LIMBS - 1) {
            self[i + 1] += self[i] >> Self::BITS;
        }
    }

    fn mask(&mut self) {
        for i in 0..LIMBS {
            self[i] &= Self::MASKS[i];
        }
    }

    fn reduce(&mut self) {
        let mut diff = Self::ZERO;
        let mut borrow = 0u32;
        for i in 0..LIMBS {
            let (d1, b1) = self[i].overflowing_sub(P::MOD[i] as u32);
            let (d2, b2) = d1.overflowing_sub(borrow);
            diff[i] = d2 & Self::MASKS[i];
            borrow = (b1 | b2) as u32;
        }
        *self = Self::select(&diff, self, borrow as u64);
    }

    fn round(t: &mut [u64], i: usize) {
        let x = ((t[i] as u32).wrapping_mul(P::N0 as u32) & Self::MASKS[0]) as u64;
        for j in 0..LIMBS {
            t[i + j] += x * P::MOD[j] as u64;
        }
        t[i + 1] += t[i] >> Self::BITS;
    }
}

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

    pub(crate) fn mul(self, rhs: Self) -> Self {
        let ar = self.montgomery_mul(Self::R2);
        ar.montgomery_mul(rhs)
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
        t[11] += t[10] >> Self::BITS;
        t[12] += t[11] >> Self::BITS;
        t[13] += t[12] >> Self::BITS;
        t[14] += t[13] >> Self::BITS;
        t[15] += t[14] >> Self::BITS;
        t[16] += t[15] >> Self::BITS;
        t[17] += t[16] >> Self::BITS;
        t[18] += t[17] >> Self::BITS;
        t[19] += t[18] >> Self::BITS;
        let mut s = Self::new([
            t[10], t[11], t[12], t[13], t[14], t[15], t[16], t[17], t[18], t[19],
        ]);
        s.mask();
        s.reduce();
        s
    }
}
