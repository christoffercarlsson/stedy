use {
    crate::{
        traits::{MontgomeryParams, WeierstrassScalar},
        utils::{wipe, Choice, Secret},
    },
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[cfg_attr(target_pointer_width = "32", path = "scalar32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar64.rs")]
mod scalar_p256;

use scalar_p256::ScalarP256Inner;

#[derive(Clone, Copy)]
pub struct ScalarP256Params;

impl MontgomeryParams<4> for ScalarP256Params {
    const MOD: [u64; 4] = [
        17562291160714782033,
        13611842547513532036,
        18446744073709551615,
        18446744069414584320,
    ];
    const ONE: [u64; 4] = [884452912994769583, 4834901526196019579, 0, 4294967295];
    const R2: [u64; 4] = [
        9449762124159643298,
        5087230966250696614,
        2901921493521525849,
        7413256579398063648,
    ];
    const N0: u64 = 14758798090332847183;
}

#[derive(Clone)]
pub struct ScalarP256(Secret<ScalarP256Inner>);

const HALF_MOD_N: [u8; 32] = [
    127, 255, 255, 255, 128, 0, 0, 0, 127, 255, 255, 255, 255, 255, 255, 255, 222, 115, 125, 86,
    211, 139, 207, 66, 121, 220, 229, 97, 126, 49, 146, 169,
];
const HALF_ONES: [u8; 32] = [
    0, 0, 0, 0, 127, 255, 255, 255, 128, 0, 0, 0, 0, 0, 0, 0, 33, 140, 130, 169, 44, 116, 48, 189,
    134, 35, 26, 158, 129, 206, 109, 87,
];

impl ScalarP256Inner {
    const ORDER: [u8; 32] = [
        255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 188, 230, 250, 173,
        167, 23, 158, 132, 243, 185, 202, 194, 252, 99, 37, 81,
    ];
    #[cfg(target_pointer_width = "64")]
    const ORDER_MINUS_2: [u8; 32] = [
        255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 188, 230, 250, 173,
        167, 23, 158, 132, 243, 185, 202, 194, 252, 99, 37, 79,
    ];

    fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        let size = slice.len().min(32);
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

    fn to_le_words(self) -> [u64; 4] {
        let bytes = self.to_le_bytes();
        let (chunks, _) = bytes.as_chunks::<8>();
        let mut words = [0u64; 4];
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u64::from_le_bytes(*chunk);
        }
        words
    }
}

impl Add for ScalarP256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(Secret::from((*self.0.get()).add(*rhs.0.get())))
    }
}

impl AddAssign for ScalarP256 {
    fn add_assign(&mut self, rhs: Self) {
        *self = Self(Secret::from((*self.0.get()).add(*rhs.0.get())));
    }
}

impl Sub for ScalarP256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(Secret::from((*self.0.get()).sub(*rhs.0.get())))
    }
}

impl SubAssign for ScalarP256 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = Self(Secret::from((*self.0.get()).sub(*rhs.0.get())));
    }
}

impl Neg for ScalarP256 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(Secret::from((*self.0.get()).neg()))
    }
}

impl Mul for ScalarP256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(Secret::from((*self.0.get()).mul(*rhs.0.get())))
    }
}

impl MulAssign for ScalarP256 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = Self(Secret::from((*self.0.get()).mul(*rhs.0.get())));
    }
}

impl From<&[u8; 32]> for ScalarP256 {
    fn from(value: &[u8; 32]) -> Self {
        Self(Secret::from(ScalarP256Inner::from_be_bytes(value)))
    }
}

impl From<[u8; 32]> for ScalarP256 {
    fn from(value: [u8; 32]) -> Self {
        Self::from(&value)
    }
}

impl From<&[u8]> for ScalarP256 {
    fn from(value: &[u8]) -> Self {
        Self(Secret::from(ScalarP256Inner::from_slice(value)))
    }
}

impl From<ScalarP256> for [u8; 32] {
    fn from(value: ScalarP256) -> Self {
        value.0.get().to_be_bytes()
    }
}

impl From<&ScalarP256> for [u8; 32] {
    fn from(value: &ScalarP256) -> Self {
        value.0.get().to_be_bytes()
    }
}

impl WeierstrassScalar for ScalarP256 {
    const ORDER_BITS: usize = 256;
    const ORDER: Self::Bytes = ScalarP256Inner::ORDER;

    type Bytes = [u8; 32];
    type Radix16 = [i8; 65];
    type Naf5 = [i8; 257];

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
        let mut t = Secret::from([0i8; 65]);
        for i in 0..32 {
            t[2 * i] = (s[i] & 15) as i8;
            t[2 * i + 1] = ((s[i] >> 4) & 15) as i8;
        }
        for i in 0..64 {
            let carry = (t[i] + 8) >> 4;
            t[i] -= carry << 4;
            t[i + 1] += carry;
        }
        wipe(&mut s);
        *t.get()
    }

    fn non_adjacent_form_5(&self) -> Self::Naf5 {
        let mut words = [0u64; 5];
        words[..4].copy_from_slice(&self.0.get().to_le_words());
        let mut naf = [0i8; 257];
        let mut pos = 0usize;
        let mut carry = 0u64;
        while pos < 257 {
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
