use {
    crate::{
        traits::{EdwardsScalar, MontgomeryParams},
        utils::{wipe, Choice, Secret},
    },
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg},
};

#[cfg_attr(target_pointer_width = "32", path = "scalar32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar64.rs")]
mod scalar448;

use scalar448::Scalar448Inner;

#[derive(Clone, Copy)]
pub struct Scalar448Params;

impl MontgomeryParams<7> for Scalar448Params {
    const MOD: [u64; 7] = [
        2556006723728458995,
        2408513697996967765,
        14145484589129676432,
        18446744071508206569,
        18446744073709551615,
        18446744073709551615,
        4611686018427387903,
    ];
    const ONE: [u64; 7] = [
        8222717178795715636,
        8812689281721680555,
        17205037938319500735,
        8805380184,
        0,
        0,
        0,
    ];
    const R2: [u64; 7] = [
        16380597172113742688,
        8859473595851707865,
        965703414319814745,
        12544723377189083192,
        1917620071967259716,
        2329131455307870383,
        3747743906366994217,
    ];
    const N0: u64 = 269446386856070085;
}

#[derive(Clone)]
pub struct Scalar448(Secret<Scalar448Inner>);

const ORDER: [u8; 57] = [
    243, 68, 88, 171, 146, 194, 120, 35, 85, 143, 197, 141, 114, 194, 108, 33, 144, 54, 214, 174,
    73, 219, 78, 196, 233, 35, 202, 124, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 63, 0,
];

const HALF_MOD_L: [u8; 57] = [
    122, 34, 172, 85, 73, 97, 188, 145, 170, 199, 226, 70, 57, 97, 182, 16, 72, 27, 107, 215, 164,
    109, 39, 226, 244, 17, 101, 190, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 31, 0,
];

const HALF_ONES: [u8; 57] = [
    121, 60, 34, 165, 242, 59, 55, 160, 99, 29, 196, 187, 29, 124, 49, 55, 5, 251, 253, 42, 71,
    218, 112, 68, 108, 62, 29, 42, 6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 32, 0,
];

impl Add for Scalar448 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(Secret::from((*self.0.get()).add(*rhs.0.get())))
    }
}

impl AddAssign for Scalar448 {
    fn add_assign(&mut self, rhs: Self) {
        *self = Self(Secret::from((*self.0.get()).add(*rhs.0.get())));
    }
}

impl Mul for Scalar448 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(Secret::from((*self.0.get()).mul(*rhs.0.get())))
    }
}

impl MulAssign for Scalar448 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = Self(Secret::from((*self.0.get()).mul(*rhs.0.get())));
    }
}

impl Neg for Scalar448 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(Secret::from((*self.0.get()).neg()))
    }
}

impl From<[u8; 57]> for Scalar448 {
    fn from(value: [u8; 57]) -> Self {
        Self(Secret::from(Scalar448Inner::from_le_slice(&value)))
    }
}

impl From<[u8; 114]> for Scalar448 {
    fn from(value: [u8; 114]) -> Self {
        Self(Secret::from(Scalar448Inner::from_le_slice(&value)))
    }
}

impl From<Scalar448> for [u8; 57] {
    fn from(value: Scalar448) -> Self {
        Self::from(&value)
    }
}

impl From<&Scalar448> for [u8; 57] {
    fn from(value: &Scalar448) -> Self {
        let mut bytes = [0u8; 57];
        bytes[..56].copy_from_slice(&value.0.get().to_le_bytes());
        bytes
    }
}

impl EdwardsScalar for Scalar448 {
    type Bytes = [u8; 57];
    type SecretBytes = [u8; 57];
    type WideBytes = [u8; 114];
    type Radix16 = [i8; 114];
    type Naf5 = [i8; 456];

    fn split(bytes: &[u8; 114]) -> ([u8; 57], [u8; 57]) {
        let (halves, _) = bytes.as_chunks::<57>();
        (halves[0], halves[1])
    }

    fn clamp(bytes: &mut [u8; 57]) {
        bytes[0] &= 252;
        bytes[55] |= 128;
        bytes[56] = 0;
    }

    fn is_canonical(bytes: &[u8; 57]) -> Choice {
        let mut borrow = 0u16;
        for (byte, order) in bytes.iter().zip(ORDER.iter()) {
            let diff = (*byte as u16)
                .wrapping_sub(*order as u16)
                .wrapping_sub(borrow);
            borrow = (diff >> 8) & 1;
        }
        Choice::nonzero(borrow)
    }

    fn as_radix_16(&self) -> Self::Radix16 {
        let mut s: [u8; 57] = self.into();
        let mut t = Secret::from([0i8; 114]);
        for i in 0..57 {
            t[2 * i] = (s[i] & 15) as i8;
            t[2 * i + 1] = ((s[i] >> 4) & 15) as i8;
        }
        for i in 0..113 {
            let carry = (t[i] + 8) >> 4;
            t[i] -= carry << 4;
            t[i + 1] += carry;
        }
        wipe(&mut s);
        *t.get()
    }

    fn non_adjacent_form_5(&self) -> Self::Naf5 {
        let mut naf = [0i8; 456];
        let bytes: [u8; 57] = self.into();
        let mut padded = [0u8; 64];
        padded[..57].copy_from_slice(&bytes);
        let (chunks, _) = padded.as_chunks::<8>();
        let mut words = [0u64; 9];
        for (word, chunk) in words.iter_mut().zip(chunks) {
            *word = u64::from_le_bytes(*chunk);
        }
        let mut pos = 0usize;
        let mut carry = 0u64;
        while pos < 456 {
            let word = pos / 64;
            let bit = pos % 64;
            let bits: u64 = if bit <= 59 {
                words[word] >> bit
            } else {
                (words[word] >> bit) | (words[word + 1] << (64 - bit))
            };
            let window = carry + (bits & 31);
            if (window & 1) == 0 {
                pos += 1;
                continue;
            }
            if window < 16 {
                carry = 0;
                naf[pos] = window as i8;
            } else {
                carry = 1;
                naf[pos] = (window as i8).wrapping_sub(32);
            }
            pos += 5;
        }
        naf
    }

    fn as_signed_bits(&self) -> Self::SecretBytes {
        (self.clone() * Self::from(HALF_MOD_L) + Self::from(HALF_ONES)).into()
    }
}
