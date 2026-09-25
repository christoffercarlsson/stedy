use {
    crate::{secret::SecretDigits, traits::WeierstrassScalar, utils::wipe, Secret},
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[cfg_attr(target_pointer_width = "32", path = "scalar32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar64.rs")]
mod scalar_p521;

pub use scalar_p521::ScalarP521;
use scalar_p521::ScalarP521Inner;

impl ScalarP521Inner {
    const ORDER: [u8; 66] = [
        1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 250, 81, 134,
        135, 131, 191, 47, 150, 107, 127, 204, 1, 72, 247, 9, 165, 208, 59, 181, 201, 184, 137,
        156, 71, 174, 187, 111, 183, 30, 145, 56, 100, 9,
    ];
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
        Self::from_bytes(&bytes)
    }

    fn invert(self) -> Self {
        let mut table = [Self::R; 16];
        table[1] = self;
        for i in 2..16 {
            table[i] = table[i - 1].mul(self);
        }
        let mut result = Self::R;
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
        Secret::from((*self.get()).add(*rhs.get()))
    }
}

impl AddAssign for ScalarP521 {
    fn add_assign(&mut self, rhs: Self) {
        *self = Secret::from((*self.get()).add(*rhs.get()));
    }
}

impl Sub for ScalarP521 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Secret::from((*self.get()).sub(*rhs.get()))
    }
}

impl SubAssign for ScalarP521 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = Secret::from((*self.get()).sub(*rhs.get()));
    }
}

impl Neg for ScalarP521 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Secret::from((*self.get()).neg())
    }
}

impl Mul for ScalarP521 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Secret::from((*self.get()).mul(*rhs.get()))
    }
}

impl MulAssign for ScalarP521 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = Secret::from((*self.get()).mul(*rhs.get()));
    }
}

impl PartialEq for ScalarP521 {
    fn eq(&self, other: &Self) -> bool {
        self.get().eq(other.get())
    }
}

impl Eq for ScalarP521 {}

impl From<&[u8; 66]> for ScalarP521 {
    fn from(value: &[u8; 66]) -> Self {
        Secret::from(ScalarP521Inner::from_bytes(value))
    }
}

impl From<[u8; 66]> for ScalarP521 {
    fn from(value: [u8; 66]) -> Self {
        Self::from(&value)
    }
}

impl From<&[u8]> for ScalarP521 {
    fn from(value: &[u8]) -> Self {
        Secret::from(ScalarP521Inner::from_slice(value))
    }
}

impl From<ScalarP521> for [u8; 66] {
    fn from(value: ScalarP521) -> Self {
        value.get().to_bytes()
    }
}

impl From<&ScalarP521> for [u8; 66] {
    fn from(value: &ScalarP521) -> Self {
        value.get().to_bytes()
    }
}

impl WeierstrassScalar for ScalarP521 {
    const ORDER_BITS: usize = 521;
    const ORDER: Self::Bytes = ScalarP521Inner::ORDER;

    type Bytes = [u8; 66];
    type Radix16 = SecretDigits<132>;
    type Naf5 = [i8; 528];

    fn is_zero(&self) -> bool {
        self.get().is_zero()
    }

    fn invert(self) -> Self {
        Secret::from(self.get().invert())
    }

    fn as_radix_16(&self) -> Self::Radix16 {
        let mut s = self.get().to_le_bytes();
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
        t
    }

    fn non_adjacent_form_5(&self) -> Self::Naf5 {
        let mut words = [0u64; 10];
        words[..9].copy_from_slice(&self.get().to_le_words());
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
