use {
    crate::traits::WeierstrassScalar,
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[cfg_attr(target_pointer_width = "32", path = "scalar32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar64.rs")]
mod scalar_p384;

pub use scalar_p384::ScalarP384;

impl ScalarP384 {
    const ORDER: [u8; 48] = [
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 199, 99, 77, 129, 244, 55, 45, 223, 88, 26, 13, 178, 72, 176,
        167, 122, 236, 236, 25, 106, 204, 197, 41, 115,
    ];
    const ORDER_MINUS_2: [u8; 48] = [
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 199, 99, 77, 129, 244, 55, 45, 223, 88, 26, 13, 178, 72, 176,
        167, 122, 236, 236, 25, 106, 204, 197, 41, 113,
    ];

    fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 48];
        let size = slice.len().min(48);
        bytes[..size].copy_from_slice(&slice[..size]);
        Self::from(&bytes)
    }

    fn invert(self) -> Self {
        let mut table = [Self::R; 16];
        table[1] = self;
        for i in 2..16 {
            table[i] = table[i - 1] * self;
        }
        let mut result = Self::R;
        for byte in Self::ORDER_MINUS_2 {
            result = result.pow2n(4) * table[(byte >> 4) as usize];
            result = result.pow2n(4) * table[(byte & 0x0f) as usize];
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
        self.add(rhs)
    }
}

impl AddAssign for ScalarP384 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Sub for ScalarP384 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(rhs)
    }
}

impl SubAssign for ScalarP384 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl Neg for ScalarP384 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl Mul for ScalarP384 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl MulAssign for ScalarP384 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl PartialEq for ScalarP384 {
    fn eq(&self, other: &Self) -> bool {
        self.eq(other)
    }
}

impl Eq for ScalarP384 {}

impl From<&[u8; 48]> for ScalarP384 {
    fn from(value: &[u8; 48]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<[u8; 48]> for ScalarP384 {
    fn from(value: [u8; 48]) -> Self {
        Self::from(&value)
    }
}

impl From<&[u8]> for ScalarP384 {
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}

impl From<ScalarP384> for [u8; 48] {
    fn from(value: ScalarP384) -> Self {
        value.to_bytes()
    }
}

impl From<&ScalarP384> for [u8; 48] {
    fn from(value: &ScalarP384) -> Self {
        Self::from(*value)
    }
}

impl WeierstrassScalar for ScalarP384 {
    const ORDER_BITS: usize = 384;
    const ORDER: Self::Bytes = Self::ORDER;

    type Bytes = [u8; 48];
    type Radix16 = [i8; 97];
    type Naf5 = [i8; 385];

    fn is_zero(&self) -> bool {
        self.is_zero()
    }

    fn invert(self) -> Self {
        self.invert()
    }

    fn as_radix_16(&self) -> Self::Radix16 {
        let s = (*self).to_le_bytes();
        let mut t = [0i8; 97];
        for i in 0..48 {
            t[2 * i] = (s[i] & 15) as i8;
            t[2 * i + 1] = ((s[i] >> 4) & 15) as i8;
        }
        for i in 0..96 {
            let carry = (t[i] + 8) >> 4;
            t[i] -= carry << 4;
            t[i + 1] += carry;
        }
        t
    }

    fn non_adjacent_form_5(&self) -> Self::Naf5 {
        let mut words = [0u64; 7];
        words[..6].copy_from_slice(&self.to_le_words());
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
