use {crate::traits::MontgomeryParams, core::marker::PhantomData};

#[cfg(target_pointer_width = "32")]
mod words {
    pub(super) type Word = u32;
    pub(super) type WideWord = u64;
}

#[cfg(target_pointer_width = "64")]
mod words {
    pub(super) type Word = u64;
    pub(super) type WideWord = u128;
}

use words::*;

#[derive(Clone, Copy)]
pub struct Montgomery<const LIMBS: usize, P>([Word; LIMBS], PhantomData<P>)
where
    P: MontgomeryParams<LIMBS>;

macro_rules! impl_montgomery {
    ($LIMBS:literal) => {
        impl<P> Montgomery<$LIMBS, P>
        where
            P: MontgomeryParams<$LIMBS>,
        {
            pub(crate) const R: Self = Self::from_limbs(P::R);
            pub(crate) const R2: Self = Self::from_limbs(P::R2);
            pub(crate) const ZERO: Self = Self::from_limbs([0; $LIMBS]);
            pub(crate) const ONE: Self = {
                let mut limbs = [0; $LIMBS];
                limbs[0] = 1;
                Self::from_limbs(limbs)
            };
            pub(crate) const MASKS: [Word; $LIMBS] = {
                let mut masks = [0; $LIMBS];
                let mut i = 0;
                while i < $LIMBS - 1 {
                    masks[i] = (1 << P::BITS) - 1;
                    i += 1;
                }
                masks[$LIMBS - 1] = (1 << P::TOP_BITS) - 1;
                masks
            };
            pub(crate) const MASK: Word = Self::MASKS[0];
            pub(crate) const TOP_MASK: Word = Self::MASKS[$LIMBS - 1];

            pub(crate) const fn from_limbs(limbs: [u64; $LIMBS]) -> Self {
                let mut words = [0 as Word; $LIMBS];
                let mut i = 0;
                while i < $LIMBS {
                    words[i] = limbs[i] as Word;
                    i += 1;
                }
                Self(words, PhantomData::<P>)
            }

            pub(crate) fn swap(a: &mut Self, b: &mut Self, condition: Word) {
                let mask = ((condition != 0) as Word).wrapping_neg();
                for i in 0..$LIMBS {
                    let t = mask & (a[i] ^ b[i]);
                    a.0[i] ^= t;
                    b.0[i] ^= t;
                }
            }

            pub(crate) fn select(a: &Self, b: &Self, condition: Word) -> Self {
                let mut x = *a;
                let mut y = *b;
                Self::swap(&mut x, &mut y, condition);
                x
            }

            pub(crate) fn eq(&self, other: &Self) -> bool {
                let mut result = 0;
                for i in 0..$LIMBS {
                    result |= self[i] ^ other[i];
                }
                result == 0
            }

            pub(crate) fn is_zero(&self) -> bool {
                self.eq(&Self::ZERO)
            }

            pub(crate) fn add(self, rhs: Self) -> Self {
                let mut result = Self::ZERO;
                for i in 0..$LIMBS {
                    result[i] = self[i] + rhs[i];
                }
                result.carry();
                result.mask();
                result.reduce();
                result
            }

            pub(crate) fn sub(self, rhs: Self) -> Self {
                let mut diff = Self::ZERO;
                let mut borrow = 0 as Word;
                for i in 0..$LIMBS {
                    let (d1, b1) = self[i].overflowing_sub(rhs[i]);
                    let (d2, b2) = d1.overflowing_sub(borrow);
                    diff[i] = d2 & Self::MASKS[i];
                    borrow = (b1 | b2) as Word;
                }
                let mask = borrow.wrapping_neg();
                let mut carry = 0 as Word;
                for i in 0..$LIMBS {
                    let sum = diff[i] as WideWord
                        + (P::MOD[i] as Word & mask) as WideWord
                        + carry as WideWord;
                    diff[i] = (sum as Word) & Self::MASKS[i];
                    carry = (sum >> P::BITS) as Word;
                }
                diff
            }

            pub(crate) fn neg(self) -> Self {
                let mut diff = Self::ZERO;
                let mut borrow = 0 as Word;
                for i in 0..$LIMBS {
                    let (d1, b1) = (P::MOD[i] as Word).overflowing_sub(self[i]);
                    let (d2, b2) = d1.overflowing_sub(borrow);
                    diff[i] = d2 & Self::MASKS[i];
                    borrow = (b1 | b2) as Word;
                }
                Self::select(&diff, &Self::ZERO, self.is_zero() as Word)
            }

            pub(crate) fn enter_montgomery(self) -> Self {
                self.montgomery_mul(Self::R2)
            }

            pub(crate) fn exit_montgomery(self) -> Self {
                self.montgomery_mul(Self::ONE)
            }

            pub(crate) fn mul(self, rhs: Self) -> Self {
                self.montgomery_mul(rhs)
            }

            pub(crate) fn square(self) -> Self {
                self.montgomery_square()
            }

            pub(crate) fn pow2n(self, n: usize) -> Self {
                let mut x = self.square();
                for _ in 1..n {
                    x = x.square();
                }
                x
            }

            fn carry(&mut self) {
                for i in 0..($LIMBS - 1) {
                    self[i + 1] += self[i] >> P::BITS;
                }
            }

            fn mask(&mut self) {
                for i in 0..$LIMBS {
                    self[i] &= Self::MASK;
                }
            }

            fn reduce(&mut self) {
                let mut diff = Self::ZERO;
                let mut borrow = 0 as Word;
                for i in 0..$LIMBS {
                    let (d1, b1) = self[i].overflowing_sub(P::MOD[i] as Word);
                    let (d2, b2) = d1.overflowing_sub(borrow);
                    diff[i] = d2 & Self::MASKS[i];
                    borrow = (b1 | b2) as Word;
                }
                *self = Self::select(&diff, self, borrow);
            }

            fn round(t: &mut [WideWord], i: usize) {
                let x = ((t[i] as Word).wrapping_mul(P::N0 as Word) & Self::MASKS[0]) as WideWord;
                for j in 0..$LIMBS {
                    t[i + j] += x * P::MOD[j] as WideWord;
                }
                t[i + 1] += t[i] >> P::BITS;
            }
        }

        impl<P: MontgomeryParams<$LIMBS>> Index<usize> for Montgomery<$LIMBS, P> {
            type Output = Word;

            fn index(&self, index: usize) -> &Self::Output {
                &self.0[index]
            }
        }

        impl<P: MontgomeryParams<$LIMBS>> IndexMut<usize> for Montgomery<$LIMBS, P> {
            fn index_mut(&mut self, index: usize) -> &mut Self::Output {
                &mut self.0[index]
            }
        }
    };
}

#[cfg_attr(target_pointer_width = "32", path = "montgomery/montgomery32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "montgomery/montgomery64.rs")]
mod monty;
