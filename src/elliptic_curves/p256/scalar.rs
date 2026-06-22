use {
    crate::traits::WeierstrassScalar,
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[cfg_attr(target_pointer_width = "32", path = "scalar32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar64.rs")]
mod scalar_p256;

pub use scalar_p256::ScalarP256;

impl ScalarP256 {
    const ORDER: [u8; 32] = [
        255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 188, 230, 250, 173,
        167, 23, 158, 132, 243, 185, 202, 194, 252, 99, 37, 81,
    ];
    const ORDER_MINUS_2: [u8; 32] = [
        255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 188, 230, 250, 173,
        167, 23, 158, 132, 243, 185, 202, 194, 252, 99, 37, 79,
    ];

    fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        let size = slice.len().min(32);
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
        self.add(rhs)
    }
}

impl AddAssign for ScalarP256 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Sub for ScalarP256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(rhs)
    }
}

impl SubAssign for ScalarP256 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl Neg for ScalarP256 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl Mul for ScalarP256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl MulAssign for ScalarP256 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl PartialEq for ScalarP256 {
    fn eq(&self, other: &Self) -> bool {
        self.eq(other)
    }
}

impl Eq for ScalarP256 {}

impl From<&[u8; 32]> for ScalarP256 {
    fn from(value: &[u8; 32]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<[u8; 32]> for ScalarP256 {
    fn from(value: [u8; 32]) -> Self {
        Self::from(&value)
    }
}

impl From<&[u8]> for ScalarP256 {
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}

impl From<ScalarP256> for [u8; 32] {
    fn from(value: ScalarP256) -> Self {
        value.to_bytes()
    }
}

impl From<&ScalarP256> for [u8; 32] {
    fn from(value: &ScalarP256) -> Self {
        Self::from(*value)
    }
}

impl WeierstrassScalar for ScalarP256 {
    const ORDER_BITS: usize = 256;
    const ORDER: Self::Bytes = Self::ORDER;

    type Bytes = [u8; 32];
    type Radix16 = [i8; 65];
    type Naf5 = [i8; 257];

    fn is_zero(&self) -> bool {
        self.is_zero()
    }

    fn invert(self) -> Self {
        self.invert()
    }

    fn as_radix_16(&self) -> Self::Radix16 {
        let s = (*self).to_le_bytes();
        let mut t = [0i8; 65];
        for i in 0..32 {
            t[2 * i] = (s[i] & 15) as i8;
            t[2 * i + 1] = ((s[i] >> 4) & 15) as i8;
        }
        for i in 0..64 {
            let carry = (t[i] + 8) >> 4;
            t[i] -= carry << 4;
            t[i + 1] += carry;
        }
        t
    }

    fn non_adjacent_form_5(&self) -> Self::Naf5 {
        let mut words = [0u64; 5];
        words[..4].copy_from_slice(&self.to_le_words());
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
