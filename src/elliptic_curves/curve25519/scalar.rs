use {
    crate::{
        secret::SecretDigits,
        traits::EdwardsScalar,
        utils::{wipe, Choice},
        Secret,
    },
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg},
};

#[cfg_attr(target_pointer_width = "32", path = "scalar32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "scalar64.rs")]
mod scalar25519;

pub use scalar25519::Scalar25519;
use scalar25519::Scalar25519Inner;

const ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

const HALF_MOD_L: [u8; 32] = [
    0xf7, 0xe9, 0x7a, 0x2e, 0x8d, 0x31, 0x09, 0x2c, 0x6b, 0xce, 0x7b, 0x51, 0xef, 0x7c, 0x6f, 0x0a,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
];

const HALF_ONES: [u8; 32] = [
    0x8e, 0x4a, 0xcc, 0x46, 0xba, 0x18, 0x76, 0x6b, 0xb8, 0xe7, 0xbe, 0x39, 0xfa, 0xad, 0x77, 0x63,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07,
];

impl Add for Scalar25519 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Secret::from((*self.get()).add(*rhs.get()))
    }
}

impl AddAssign for Scalar25519 {
    fn add_assign(&mut self, rhs: Self) {
        *self = Secret::from((*self.get()).add(*rhs.get()));
    }
}

impl Mul for Scalar25519 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Secret::from((*self.get()).mul(*rhs.get()))
    }
}

impl MulAssign for Scalar25519 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = Secret::from((*self.get()).mul(*rhs.get()));
    }
}

impl Neg for Scalar25519 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Secret::from((*self.get()).neg())
    }
}

impl From<[u8; 32]> for Scalar25519 {
    fn from(value: [u8; 32]) -> Self {
        Secret::from(Scalar25519Inner::from_bytes(&value))
    }
}

impl From<Secret<[u8; 32]>> for Scalar25519 {
    fn from(value: Secret<[u8; 32]>) -> Self {
        Secret::from(Scalar25519Inner::from_bytes(value.get()))
    }
}

impl From<[u8; 64]> for Scalar25519 {
    fn from(value: [u8; 64]) -> Self {
        Secret::from(Scalar25519Inner::from_wide_bytes(&value))
    }
}

impl From<Scalar25519> for [u8; 32] {
    fn from(value: Scalar25519) -> Self {
        value.get().to_bytes()
    }
}

impl From<&Scalar25519> for [u8; 32] {
    fn from(value: &Scalar25519) -> Self {
        value.get().to_bytes()
    }
}

impl EdwardsScalar for Scalar25519 {
    type Bytes = [u8; 32];
    type SecretBytes = Secret<[u8; 32]>;
    type WideBytes = [u8; 64];
    type Radix16 = SecretDigits<64>;
    type Naf5 = [i8; 256];

    fn split(bytes: &[u8; 64]) -> (Secret<[u8; 32]>, Secret<[u8; 32]>) {
        let mut a = Secret::from([0u8; 32]);
        let mut b = Secret::from([0u8; 32]);
        a.as_mut().copy_from_slice(&bytes[..32]);
        b.as_mut().copy_from_slice(&bytes[32..]);
        (a, b)
    }

    fn clamp(bytes: &mut Secret<[u8; 32]>) {
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
    }

    fn is_canonical(bytes: &[u8; 32]) -> Choice {
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
        let mut s: [u8; 32] = self.into();
        let mut t = Secret::from([0i8; 64]);
        for i in 0..32 {
            t[2 * i] = (s[i] & 15) as i8;
            t[2 * i + 1] = ((s[i] >> 4) & 15) as i8;
        }
        for i in 0..63 {
            let carry = (t[i] + 8) >> 4;
            t[i] -= carry << 4;
            t[i + 1] += carry;
        }
        wipe(&mut s);
        t
    }

    fn non_adjacent_form_5(&self) -> Self::Naf5 {
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

    fn as_signed_bits(&self) -> Self::SecretBytes {
        let bits: [u8; 32] = (self.clone() * Self::from(HALF_MOD_L) + Self::from(HALF_ONES)).into();
        Secret::from(bits)
    }
}
