#[cfg(target_pointer_width = "32")]
mod scalar32;
#[cfg(target_pointer_width = "64")]
mod scalar64;

use {crate::traits::Scalar, core::ops::Mul};

#[cfg(target_pointer_width = "32")]
pub use scalar32::Scalar25519;

#[cfg(target_pointer_width = "64")]
pub use scalar64::Scalar25519;

impl Scalar25519 {
    pub(crate) fn as_radix_16(&self) -> [i8; 64] {
        let s: [u8; 32] = self.into();
        let mut t = [0i8; 64];
        for i in 0..32 {
            t[2 * i] = (s[i] & 15) as i8;
            t[2 * i + 1] = ((s[i] >> 4) & 15) as i8;
        }
        for i in 0..63 {
            let carry = (t[i] + 8) >> 4;
            t[i] -= carry << 4;
            t[i + 1] += carry;
        }
        t
    }

    pub(crate) fn non_adjacent_form_5(&self) -> [i8; 256] {
        let mut naf = [0i8; 256];
        let bytes: [u8; 32] = self.into();
        let (chunks, _) = bytes.as_chunks::<8>();
        let words = [
            u64::from_le_bytes(chunks[0]),
            u64::from_le_bytes(chunks[1]),
            u64::from_le_bytes(chunks[2]),
            u64::from_le_bytes(chunks[3]),
            0,
        ];
        let mut pos = 0usize;
        let mut carry = 0u64;
        while pos < 256 {
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

impl Mul for Scalar25519 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let ar = self.montgomery_mul(Self::R2);
        ar.montgomery_mul(rhs)
    }
}

impl From<&Scalar25519> for [u8; 32] {
    fn from(value: &Scalar25519) -> Self {
        Self::from(*value)
    }
}

impl Scalar for Scalar25519 {
    type Bytes = [u8; 32];
    type WideBytes = [u8; 64];

    fn concat(a: &[u8; 32], b: &[u8; 32]) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(a);
        bytes[32..].copy_from_slice(b);
        bytes
    }

    fn split(bytes: &[u8; 64]) -> (&[u8; 32], &[u8; 32]) {
        let a = <&[u8; 32]>::try_from(&bytes[..32]).expect("Bytes is half the size of WideBytes");
        let b = <&[u8; 32]>::try_from(&bytes[32..]).expect("Bytes is half the size of WideBytes");
        (a, b)
    }

    fn clamp(bytes: &mut [u8; 32]) {
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
    }
}
