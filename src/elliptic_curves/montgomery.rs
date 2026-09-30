use {
    crate::{
        traits::MontgomeryParams,
        utils::{unsigned_mul, Choice},
    },
    core::marker::PhantomData,
};

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

const WORD_BYTES: usize = Word::BITS as usize / 8;

#[derive(Clone, Copy)]
pub struct Montgomery<const N: usize, P>([Word; N], PhantomData<P>);

macro_rules! impl_montgomery {
    ($N:literal, $LIMBS:literal, $BYTES:literal) => {
        impl_montgomery!(@core $N, $LIMBS, $BYTES);
    };
    ($N:literal, $LIMBS:literal, $BYTES:literal, wide) => {
        impl_montgomery!(@core $N, $LIMBS, $BYTES);

        impl<P: MontgomeryParams<$LIMBS>> Montgomery<$N, P> {
            pub(crate) fn from_wide_le_bytes(bytes: &[u8; 2 * $BYTES]) -> Self {
                let (low, high) = bytes.split_at($BYTES);
                let low = Self(Self::words_from_le(low.iter()), PhantomData);
                let high = Self(Self::words_from_le(high.iter()), PhantomData);
                low.mul(Self::R2).add(high.mul(Self::R2).mul(Self::R2))
            }
        }
    };
    (@core $N:literal, $LIMBS:literal, $BYTES:literal) => {
        #[allow(dead_code)]
        impl<P: MontgomeryParams<$LIMBS>> Montgomery<$N, P> {
            pub(crate) const ZERO: Self = Self([0; $N], PhantomData);
            pub(crate) const ONE: Self = Self::from_limbs(P::ONE);
            const PLAIN_ONE: Self = {
                let mut words = [0 as Word; $N];
                words[0] = 1;
                Self(words, PhantomData)
            };
            const MOD: [Word; $N] = Self::from_limbs(P::MOD).0;
            const R2: Self = Self::from_limbs(P::R2);
            const N0: Word = P::N0 as Word;
            const BITS: usize = {
                let mut i = $LIMBS - 1;
                while i > 0 && P::MOD[i] == 0 {
                    i -= 1;
                }
                64 * i + 64 - P::MOD[i].leading_zeros() as usize
            };

            pub(crate) const fn from_limbs(value: [u64; $LIMBS]) -> Self {
                let mut words = [0 as Word; $N];
                let mut i = 0;
                while i < $N {
                    let bit = i * Word::BITS as usize;
                    words[i] = (value[bit / 64] >> (bit % 64)) as Word;
                    i += 1;
                }
                Self(words, PhantomData)
            }

            pub(crate) fn swap(a: &mut Self, b: &mut Self, condition: Choice) {
                condition.swap(&mut a.0, &mut b.0);
            }

            pub(crate) fn select(a: &Self, b: &Self, condition: Choice) -> Self {
                let mut selected = *a;
                condition.assign(&mut selected.0, &b.0);
                selected
            }

            pub(crate) fn assign(&mut self, other: &Self, condition: Choice) {
                condition.assign(&mut self.0, &other.0);
            }

            pub(crate) fn ct_eq(&self, other: &Self) -> Choice {
                Choice::eq_slice(&self.0, &other.0)
            }

            pub(crate) fn is_zero(&self) -> Choice {
                Choice::eq_slice(&self.0, &[0; $N])
            }

            pub(crate) fn add(self, rhs: Self) -> Self {
                let mut sum = [0 as Word; $N];
                let mut carry = 0;
                for i in 0..$N {
                    (sum[i], carry) = Self::adc(self.0[i], rhs.0[i], carry);
                }
                Self::reduce(sum, carry)
            }

            pub(crate) fn sub(self, rhs: Self) -> Self {
                let mut diff = [0 as Word; $N];
                let mut borrow = 0;
                for i in 0..$N {
                    (diff[i], borrow) = Self::sbb(self.0[i], rhs.0[i], borrow);
                }
                let mask = Choice::nonzero(borrow).mask::<Word>();
                let mut carry = 0;
                for i in 0..$N {
                    (diff[i], carry) = Self::adc(diff[i], Self::MOD[i] & mask, carry);
                }
                Self(diff, PhantomData)
            }

            pub(crate) fn neg(self) -> Self {
                Self::ZERO.sub(self)
            }

            pub(crate) fn mul(self, rhs: Self) -> Self {
                let mut t = [0 as Word; $N + 2];
                for i in 0..$N {
                    let mut carry = 0;
                    for j in 0..$N {
                        (t[j], carry) = Self::mac(t[j], self.0[j], rhs.0[i], carry);
                    }
                    (t[$N], t[$N + 1]) = Self::adc(t[$N], carry, 0);
                    let m = t[0].wrapping_mul(Self::N0);
                    let (_, mut carry) = Self::mac(t[0], m, Self::MOD[0], 0);
                    for j in 1..$N {
                        (t[j - 1], carry) = Self::mac(t[j], m, Self::MOD[j], carry);
                    }
                    (t[$N - 1], carry) = Self::adc(t[$N], carry, 0);
                    t[$N] = t[$N + 1] + carry;
                }
                let mut words = [0 as Word; $N];
                words.copy_from_slice(&t[..$N]);
                Self::reduce(words, t[$N])
            }

            pub(crate) fn square(self) -> Self {
                self.mul(self)
            }

            pub(crate) fn pow2n(self, n: usize) -> Self {
                let mut result = self;
                for _ in 0..n {
                    result = result.square();
                }
                result
            }

            pub(crate) fn invert_binary(self) -> Self {
                let mut value = [0 as Word; $N + 1];
                value[..$N].copy_from_slice(&self.mul(Self::PLAIN_ONE).0);
                let mut modulus = [0 as Word; $N + 1];
                modulus[..$N].copy_from_slice(&Self::MOD);
                let inverse = Self::invert_words(&value, &modulus);
                let mut words = [0 as Word; $N];
                words.copy_from_slice(&inverse[..$N]);
                Self(words, PhantomData).mul(Self::R2)
            }

            pub(crate) fn from_u32(value: u32) -> Self {
                let mut words = [0 as Word; $N];
                words[0] = value as Word;
                Self(words, PhantomData).mul(Self::R2)
            }

            pub(crate) fn from_be_bytes(bytes: &[u8; $BYTES]) -> Self {
                Self(Self::words_from_le(bytes.iter().rev()), PhantomData).mul(Self::R2)
            }

            pub(crate) fn from_le_bytes(bytes: &[u8; $BYTES]) -> Self {
                Self(Self::words_from_le(bytes.iter()), PhantomData).mul(Self::R2)
            }

            pub(crate) fn to_be_bytes(self) -> [u8; $BYTES] {
                let mut bytes = self.to_le_bytes();
                bytes.reverse();
                bytes
            }

            pub(crate) fn to_le_bytes(self) -> [u8; $BYTES] {
                let words = self.mul(Self::PLAIN_ONE).0;
                let mut bytes = [0u8; $BYTES];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = (words[i / WORD_BYTES] >> (8 * (i % WORD_BYTES))) as u8;
                }
                bytes
            }

            fn words_from_le<'a>(bytes: impl Iterator<Item = &'a u8>) -> [Word; $N] {
                let mut words = [0 as Word; $N];
                for (i, &byte) in bytes.enumerate() {
                    words[i / WORD_BYTES] |= (byte as Word) << (8 * (i % WORD_BYTES));
                }
                words
            }

            fn reduce(words: [Word; $N], top: Word) -> Self {
                let mut diff = [0 as Word; $N];
                let mut borrow = 0;
                for i in 0..$N {
                    (diff[i], borrow) = Self::sbb(words[i], Self::MOD[i], borrow);
                }
                let subtract = Choice::nonzero(top) | !Choice::nonzero(borrow);
                let mut result = Self(words, PhantomData);
                subtract.assign(&mut result.0, &diff);
                result
            }

            #[inline(always)]
            fn mac(a: Word, b: Word, c: Word, carry: Word) -> (Word, Word) {
                let t = a as WideWord + unsigned_mul(b, c) + carry as WideWord;
                (t as Word, (t >> Word::BITS) as Word)
            }

            #[inline(always)]
            fn adc(a: Word, b: Word, carry: Word) -> (Word, Word) {
                let t = a as WideWord + b as WideWord + carry as WideWord;
                (t as Word, (t >> Word::BITS) as Word)
            }

            #[inline(always)]
            fn sbb(a: Word, b: Word, borrow: Word) -> (Word, Word) {
                let t = (a as WideWord)
                    .wrapping_sub(b as WideWord)
                    .wrapping_sub(borrow as WideWord);
                (t as Word, (t >> (WideWord::BITS - 1)) as Word)
            }

            fn invert_words(
                value: &[Word; $N + 1],
                modulus: &[Word; $N + 1],
            ) -> [Word; $N + 1] {
                let mut u = *modulus;
                let mut v = *value;
                let mut r = [0 as Word; $N + 1];
                let mut s = [0 as Word; $N + 1];
                s[0] = 1;
                let mut k = 0 as Word;
                for _ in 0..2 * Self::BITS {
                    let done = Self::words_zero(&v);
                    let u_even = !Choice::nonzero(u[0] & 1);
                    let v_even = !Choice::nonzero(v[0] & 1);
                    let (u_minus_v, borrow) = Self::words_sub(&u, &v);
                    let (v_minus_u, _) = Self::words_sub(&v, &u);
                    let u_greater = !Choice::nonzero(borrow) & !Self::words_zero(&u_minus_v);
                    let halve_u = !done & u_even;
                    let halve_v = !done & !u_even & v_even;
                    let both_odd = !done & !u_even & !v_even;
                    let reduce_u = both_odd & u_greater;
                    let reduce_v = both_odd & !u_greater;
                    let mut u_half = u;
                    Self::words_shr1(&mut u_half);
                    let mut v_half = v;
                    Self::words_shr1(&mut v_half);
                    let mut u_minus_v_half = u_minus_v;
                    Self::words_shr1(&mut u_minus_v_half);
                    let mut v_minus_u_half = v_minus_u;
                    Self::words_shr1(&mut v_minus_u_half);
                    let mut r2 = r;
                    Self::words_shl1(&mut r2);
                    let mut s2 = s;
                    Self::words_shl1(&mut s2);
                    let (r_plus_s, _) = Self::words_add(&r, &s);
                    halve_u.assign(&mut u, &u_half);
                    reduce_u.assign(&mut u, &u_minus_v_half);
                    halve_v.assign(&mut v, &v_half);
                    reduce_v.assign(&mut v, &v_minus_u_half);
                    (halve_v | reduce_v).assign(&mut r, &r2);
                    reduce_u.assign(&mut r, &r_plus_s);
                    (halve_u | reduce_u).assign(&mut s, &s2);
                    reduce_v.assign(&mut s, &r_plus_s);
                    k += (!done).mask::<Word>() & 1;
                }
                let (reduced, borrow) = Self::words_sub(&r, modulus);
                (!Choice::nonzero(borrow)).assign(&mut r, &reduced);
                let (negated, _) = Self::words_sub(modulus, &r);
                r = negated;
                for i in 0..2 * Self::BITS {
                    let mut half = r;
                    let (plus_m, _) = Self::words_add(&half, modulus);
                    Choice::nonzero(half[0] & 1).assign(&mut half, &plus_m);
                    Self::words_shr1(&mut half);
                    Choice::less_than(i as Word, k).assign(&mut r, &half);
                }
                r
            }

            fn words_zero(a: &[Word; $N + 1]) -> Choice {
                Choice::eq_slice(a, &[0 as Word; $N + 1])
            }

            fn words_add(a: &[Word; $N + 1], b: &[Word; $N + 1]) -> ([Word; $N + 1], Word) {
                let mut sum = [0 as Word; $N + 1];
                let mut carry = 0;
                for i in 0..$N + 1 {
                    (sum[i], carry) = Self::adc(a[i], b[i], carry);
                }
                (sum, carry)
            }

            fn words_sub(a: &[Word; $N + 1], b: &[Word; $N + 1]) -> ([Word; $N + 1], Word) {
                let mut diff = [0 as Word; $N + 1];
                let mut borrow = 0;
                for i in 0..$N + 1 {
                    (diff[i], borrow) = Self::sbb(a[i], b[i], borrow);
                }
                (diff, borrow)
            }

            fn words_shr1(a: &mut [Word; $N + 1]) {
                for i in 0..$N + 1 {
                    let next = if i + 1 < $N + 1 {
                        a[i + 1] << (Word::BITS - 1)
                    } else {
                        0
                    };
                    a[i] = (a[i] >> 1) | next;
                }
            }

            fn words_shl1(a: &mut [Word; $N + 1]) {
                for i in (0..$N + 1).rev() {
                    let previous = if i > 0 { a[i - 1] >> (Word::BITS - 1) } else { 0 };
                    a[i] = (a[i] << 1) | previous;
                }
            }
        }
    };
}

#[cfg_attr(target_pointer_width = "32", path = "montgomery/montgomery32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "montgomery/montgomery64.rs")]
mod backend;
