use {
    crate::{
        traits::{MontgomeryParams, WeierstrassScalar},
        utils::{wipe, Choice},
        Secret,
    },
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[cfg_attr(target_pointer_width = "32", path = "scalar32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar64.rs")]
mod scalar_p521;

use scalar_p521::ScalarP521Inner;

#[derive(Clone, Copy)]
pub struct ScalarP521Params;

impl MontgomeryParams<9> for ScalarP521Params {
    const MOD: [u64; 9] = [
        13506215149420700681,
        4302566813442262958,
        9208736750959699408,
        5874531763869423211,
        18446744073709551610,
        18446744073709551615,
        18446744073709551615,
        18446744073709551615,
        511,
    ];
    const ONE: [u64; 9] = [
        18122484900538875904,
        2927982029091333069,
        1720978806102766044,
        14573676978713688877,
        204699087262476340,
        0,
        0,
        0,
        0,
    ];
    const R2: [u64; 9] = [
        1404226216438127876,
        17800401510108266147,
        1344198287485662207,
        15236274528439459334,
        15955729941216741339,
        14984550469667745342,
        6614782218913277884,
        3282565375810407749,
        61,
    ];
    const N0: u64 = 2103001588584519111;
}

#[derive(Clone)]
pub struct ScalarP521(Secret<ScalarP521Inner>);

const HALF_MOD_N: [u8; 66] = [
    0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 40, 195, 67, 193,
    223, 151, 203, 53, 191, 230, 0, 164, 123, 132, 210, 232, 29, 218, 228, 220, 68, 206, 35, 215,
    93, 183, 219, 143, 72, 156, 50, 5,
];
const HALF_ONES: [u8; 66] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 104, 199, 33, 98, 210, 19, 178, 48, 85, 204, 229, 174, 102, 185, 27, 94, 217, 48, 104, 118,
    185, 221, 188, 56, 40, 129, 202, 19, 234, 250, 131, 47, 196,
];

impl ScalarP521Inner {
    const ORDER: [u8; 66] = [
        1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 250, 81, 134,
        135, 131, 191, 47, 150, 107, 127, 204, 1, 72, 247, 9, 165, 208, 59, 181, 201, 184, 137,
        156, 71, 174, 187, 111, 183, 30, 145, 56, 100, 9,
    ];
    #[cfg(target_pointer_width = "64")]
    const ORDER_MINUS_2: [u8; 66] = [
        1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 250, 81, 134,
        135, 131, 191, 47, 150, 107, 127, 204, 1, 72, 247, 9, 165, 208, 59, 181, 201, 184, 137,
        156, 71, 174, 187, 111, 183, 30, 145, 56, 100, 7,
    ];

    fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 66];
        let size = slice.len().min(66);
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

    fn to_le_words(self) -> [u64; 9] {
        let mut words = [0u64; 9];
        let bytes = self.to_le_bytes();
        let (chunks, remainder) = bytes.as_chunks::<8>();
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u64::from_le_bytes(*chunk);
        }
        let mut dest = [0u8; 8];
        dest[..remainder.len()].copy_from_slice(remainder);
        words[8] = u64::from_le_bytes(dest);
        words
    }
}

impl Add for ScalarP521 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(Secret::from((*self.0.get()).add(*rhs.0.get())))
    }
}

impl AddAssign for ScalarP521 {
    fn add_assign(&mut self, rhs: Self) {
        *self = Self(Secret::from((*self.0.get()).add(*rhs.0.get())));
    }
}

impl Sub for ScalarP521 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(Secret::from((*self.0.get()).sub(*rhs.0.get())))
    }
}

impl SubAssign for ScalarP521 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = Self(Secret::from((*self.0.get()).sub(*rhs.0.get())));
    }
}

impl Neg for ScalarP521 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(Secret::from((*self.0.get()).neg()))
    }
}

impl Mul for ScalarP521 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(Secret::from((*self.0.get()).mul(*rhs.0.get())))
    }
}

impl MulAssign for ScalarP521 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = Self(Secret::from((*self.0.get()).mul(*rhs.0.get())));
    }
}

impl From<&[u8; 66]> for ScalarP521 {
    fn from(value: &[u8; 66]) -> Self {
        Self(Secret::from(ScalarP521Inner::from_be_bytes(value)))
    }
}

impl From<[u8; 66]> for ScalarP521 {
    fn from(value: [u8; 66]) -> Self {
        Self::from(&value)
    }
}

impl From<&[u8]> for ScalarP521 {
    fn from(value: &[u8]) -> Self {
        Self(Secret::from(ScalarP521Inner::from_slice(value)))
    }
}

impl From<ScalarP521> for [u8; 66] {
    fn from(value: ScalarP521) -> Self {
        value.0.get().to_be_bytes()
    }
}

impl From<&ScalarP521> for [u8; 66] {
    fn from(value: &ScalarP521) -> Self {
        value.0.get().to_be_bytes()
    }
}

impl WeierstrassScalar for ScalarP521 {
    const ORDER_BITS: usize = 521;
    const ORDER: Self::Bytes = ScalarP521Inner::ORDER;

    type Bytes = [u8; 66];
    type Radix16 = [i8; 132];
    type Naf5 = [i8; 528];

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
        let mut t = Secret::from([0i8; 132]);
        for i in 0..66 {
            t[2 * i] = (s[i] & 15) as i8;
            t[2 * i + 1] = ((s[i] >> 4) & 15) as i8;
        }
        for i in 0..131 {
            let carry = (t[i] + 8) >> 4;
            t[i] -= carry << 4;
            t[i + 1] += carry;
        }
        wipe(&mut s);
        *t.get()
    }

    fn non_adjacent_form_5(&self) -> Self::Naf5 {
        let mut words = [0u64; 10];
        words[..9].copy_from_slice(&self.0.get().to_le_words());
        let mut naf = [0i8; 528];
        let mut pos = 0usize;
        let mut carry = 0u64;
        while pos < 528 {
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
