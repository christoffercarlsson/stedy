use {
    crate::{traits::MontgomeryParams, utils::unsigned_mul as m},
    core::{
        array::from_fn,
        marker::PhantomData,
        ops::{Index, IndexMut},
    },
};

#[derive(Clone, Copy)]
pub struct Montgomery<const LIMBS: usize, P>([u64; LIMBS], PhantomData<P>)
where
    P: MontgomeryParams<LIMBS>;

impl<const LIMBS: usize, P> Index<usize> for Montgomery<LIMBS, P>
where
    P: MontgomeryParams<LIMBS>,
{
    type Output = u64;

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
    pub(crate) const MASK: u64 = Self::MASKS[0];
    pub(crate) const TOP_MASK: u64 = Self::MASKS[LIMBS - 1];
    pub(crate) const ZERO: Self = Self::new([0; LIMBS]);

    pub(crate) fn swap(a: &mut Self, b: &mut Self, condition: u64) {
        let mask = ((condition != 0) as u64).wrapping_neg();
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
        let mut result = Self::new(from_fn(|i| self[i] + rhs[i]));
        result.carry();
        result.mask();
        result.reduce();
        result
    }

    pub(crate) fn neg(self) -> Self {
        let mut diff = Self::ZERO;
        let mut borrow = 0u64;
        for i in 0..LIMBS {
            let (d1, b1) = P::MOD[i].overflowing_sub(self[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            diff[i] = d2 & Self::MASKS[i];
            borrow = (b1 | b2) as u64;
        }
        Self::select(&diff, &Self::ZERO, self.is_zero() as u64)
    }
}

impl<const LIMBS: usize, P> Montgomery<LIMBS, P>
where
    P: MontgomeryParams<LIMBS>,
{
    const BITS: u32 = P::BITS;
    const MASKS: [u64; LIMBS] = {
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
        Self(limbs, PhantomData::<P>)
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
        let mut borrow = 0u64;
        for i in 0..LIMBS {
            let (d1, b1) = self[i].overflowing_sub(P::MOD[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            diff[i] = d2 & Self::MASKS[i];
            borrow = (b1 | b2) as u64;
        }
        *self = Self::select(&diff, self, borrow);
    }

    fn round(t: &mut [u128], i: usize) {
        let x = ((t[i] as u64).wrapping_mul(P::N0) & Self::MASKS[0]) as u128;
        for j in 0..LIMBS {
            t[i + j] += x * P::MOD[j] as u128;
        }
        t[i + 1] += t[i] >> Self::BITS;
    }
}

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

    pub(crate) fn mul(self, rhs: Self) -> Self {
        let ar = self.montgomery_mul(Self::R2);
        ar.montgomery_mul(rhs)
    }

    fn montgomery_reduce(t: &mut [u128; 10]) -> Self {
        Self::round(t, 0);
        Self::round(t, 1);
        Self::round(t, 2);
        Self::round(t, 3);
        Self::round(t, 4);
        t[6] += t[5] >> Self::BITS;
        t[7] += t[6] >> Self::BITS;
        t[8] += t[7] >> Self::BITS;
        t[9] += t[8] >> Self::BITS;
        let mut s = Self::new([
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
