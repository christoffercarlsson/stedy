use {
    crate::{
        traits::{MontgomeryParams, WeierstrassScalar},
        utils::{wipe, Choice, Secret},
    },
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[cfg_attr(target_pointer_width = "32", path = "scalar32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar64.rs")]
mod scalar_p384;

use scalar_p384::ScalarP384Inner;

#[derive(Clone, Copy)]
pub struct ScalarP384Params;

impl MontgomeryParams<6> for ScalarP384Params {
    const MOD: [u64; 6] = [
        17072048233947408755,
        6348401684107011962,
        14367412456785391071,
        18446744073709551615,
        18446744073709551615,
        18446744073709551615,
    ];
    const ONE: [u64; 6] = [
        1374695839762142861,
        12098342389602539653,
        4079331616924160544,
        0,
        0,
        0,
    ];
    const R2: [u64; 6] = [
        3256554584917936553,
        18391999277541532697,
        13564358545871743303,
        15279949475123764421,
        4589268600508278933,
        902107514168524577,
    ];
    const N0: u64 = 7986114184663260229;
}

#[derive(Clone)]
pub struct ScalarP384(Secret<ScalarP384Inner>);

const HALF_MOD_N: [u8; 48] = [
    127, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 227, 177, 166, 192, 250, 27, 150, 239, 172, 13, 6, 217, 36, 88, 83,
    189, 118, 118, 12, 181, 102, 98, 148, 186,
];
const HALF_ONES: [u8; 48] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 78, 89, 63, 5, 228,
    105, 16, 83, 242, 249, 38, 219, 167, 172, 66, 137, 137, 243, 74, 153, 157, 107, 70,
];

impl ScalarP384Inner {
    const ORDER: [u8; 48] = [
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 199, 99, 77, 129, 244, 55, 45, 223, 88, 26, 13, 178, 72, 176,
        167, 122, 236, 236, 25, 106, 204, 197, 41, 115,
    ];
    #[cfg(target_pointer_width = "64")]
    const ORDER_MINUS_2: [u8; 48] = [
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 199, 99, 77, 129, 244, 55, 45, 223, 88, 26, 13, 178, 72, 176,
        167, 122, 236, 236, 25, 106, 204, 197, 41, 113,
    ];

    fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 48];
        let size = slice.len().min(48);
        bytes[..size].copy_from_slice(&slice[..size]);
        Self::from_be_bytes(&bytes)
    }

    #[cfg(target_pointer_width = "64")]
    fn invert(self) -> Self {
        let mut table = [Self::ONE; 16];
        table[1] = self;
        for i in 2..16 {
            table[i] = table[i - 1].mul(self);
        }
        let mut result = Self::ONE;
        for byte in Self::ORDER_MINUS_2 {
            result = result.pow2n(4).mul(table[(byte >> 4) as usize]);
            result = result.pow2n(4).mul(table[(byte & 0x0f) as usize]);
        }
        result
    }

    fn to_le_words(self) -> [u64; 6] {
        let bytes = self.to_le_bytes();
        let (chunks, _) = bytes.as_chunks::<8>();
        let mut words = [0u64; 6];
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u64::from_le_bytes(*chunk);
        }
        words
    }
}

impl Add for ScalarP384 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(Secret::from((*self.0.get()).add(*rhs.0.get())))
    }
}

impl AddAssign for ScalarP384 {
    fn add_assign(&mut self, rhs: Self) {
        *self = Self(Secret::from((*self.0.get()).add(*rhs.0.get())));
    }
}

impl Sub for ScalarP384 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(Secret::from((*self.0.get()).sub(*rhs.0.get())))
    }
}

impl SubAssign for ScalarP384 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = Self(Secret::from((*self.0.get()).sub(*rhs.0.get())));
    }
}

impl Neg for ScalarP384 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(Secret::from((*self.0.get()).neg()))
    }
}

impl Mul for ScalarP384 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(Secret::from((*self.0.get()).mul(*rhs.0.get())))
    }
}

impl MulAssign for ScalarP384 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = Self(Secret::from((*self.0.get()).mul(*rhs.0.get())));
    }
}

impl From<&[u8; 48]> for ScalarP384 {
    fn from(value: &[u8; 48]) -> Self {
        Self(Secret::from(ScalarP384Inner::from_be_bytes(value)))
    }
}

impl From<[u8; 48]> for ScalarP384 {
    fn from(value: [u8; 48]) -> Self {
        Self::from(&value)
    }
}

impl From<&[u8]> for ScalarP384 {
    fn from(value: &[u8]) -> Self {
        Self(Secret::from(ScalarP384Inner::from_slice(value)))
    }
}

impl From<ScalarP384> for [u8; 48] {
    fn from(value: ScalarP384) -> Self {
        value.0.get().to_be_bytes()
    }
}

impl From<&ScalarP384> for [u8; 48] {
    fn from(value: &ScalarP384) -> Self {
        value.0.get().to_be_bytes()
    }
}

impl WeierstrassScalar for ScalarP384 {
    const ORDER_BITS: usize = 384;
    const ORDER: Self::Bytes = ScalarP384Inner::ORDER;

    type Bytes = [u8; 48];
    type Radix16 = [i8; 97];
    type Naf5 = [i8; 385];

    fn is_zero(&self) -> Choice {
        self.0.get().is_zero()
    }

    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.get().ct_eq(other.0.get())
    }

    #[cfg(target_pointer_width = "64")]
    fn invert(self) -> Self {
        Self(Secret::from(self.0.get().invert()))
    }

    #[cfg(target_pointer_width = "32")]
    fn invert(self) -> Self {
        Self(Secret::from(self.0.get().invert_binary()))
    }

    fn as_signed_bits(&self) -> Self::Bytes {
        (self.clone() * Self::from(HALF_MOD_N) + Self::from(HALF_ONES))
            .0
            .get()
            .to_le_bytes()
    }

    fn as_radix_16(&self) -> Self::Radix16 {
        let mut s = self.0.get().to_le_bytes();
        let mut t = Secret::from([0i8; 97]);
        for i in 0..48 {
            t[2 * i] = (s[i] & 15) as i8;
            t[2 * i + 1] = ((s[i] >> 4) & 15) as i8;
        }
        for i in 0..96 {
            let carry = (t[i] + 8) >> 4;
            t[i] -= carry << 4;
            t[i + 1] += carry;
        }
        wipe(&mut s);
        *t.get()
    }

    fn non_adjacent_form_5(&self) -> Self::Naf5 {
        let mut words = [0u64; 7];
        words[..6].copy_from_slice(&self.0.get().to_le_words());
        let mut naf = [0i8; 385];
        let mut pos = 0usize;
        let mut carry = 0u64;
        while pos < 385 {
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
}
