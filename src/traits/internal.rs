use {
    crate::{
        traits::ByteArray,
        utils::{Choice, is_zero, less_than},
    },
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

pub trait EdwardsScalar:
    Sized
    + Clone
    + From<Self::Bytes>
    + From<Self::SecretBytes>
    + From<Self::WideBytes>
    + Into<Self::Bytes>
    + Add<Self, Output = Self>
    + AddAssign
    + Mul<Self, Output = Self>
    + MulAssign
    + Neg<Output = Self>
{
    type Bytes: ByteArray;
    type SecretBytes: ByteArray;
    type WideBytes: ByteArray;
    type Radix16: Copy + AsRef<[i8]>;
    type Naf5: AsRef<[i8]>;

    fn split(bytes: &Self::WideBytes) -> (Self::SecretBytes, Self::SecretBytes);

    fn clamp(bytes: &mut Self::SecretBytes);

    fn is_canonical(bytes: &Self::Bytes) -> Choice;

    fn as_radix_16(&self) -> Self::Radix16;

    fn non_adjacent_form_5(&self) -> Self::Naf5;

    fn as_signed_bits(&self) -> Self::SecretBytes;
}

pub trait MlKemParams<const K: usize> {
    const ETA1: usize;
    const ETA2: usize;
    const DU: usize;
    const DV: usize;

    type Seed: ByteArray;
    type SharedSecret: ByteArray;
    type PrivateKey: ByteArray;
    type PublicKey: ByteArray;
    type Ciphertext: ByteArray;
}

pub trait MlDsaParams<const K: usize, const L: usize> {
    const TAU: usize;
    const LAMBDA: usize;
    const GAMMA1: i32;
    const GAMMA2: i32;
    const ETA: i32;
    const BETA: i32;
    const OMEGA: usize;

    type Seed: ByteArray;
    type PrivateKey: ByteArray;
    type PublicKey: ByteArray;
    type Signature: ByteArray;
}

pub trait MontgomeryParams<const LIMBS: usize>: Copy + Clone {
    const MOD: [u64; LIMBS];
    const ONE: [u64; LIMBS];
    const R2: [u64; LIMBS];
    const N0: u64;
}

pub trait WeierstrassScalar:
    Sized
    + Clone
    + From<Self::Bytes>
    + Into<Self::Bytes>
    + Add<Self, Output = Self>
    + AddAssign
    + Sub<Self, Output = Self>
    + SubAssign
    + Mul<Self, Output = Self>
    + MulAssign
    + Neg<Output = Self>
{
    const ORDER_BITS: usize;
    const ORDER: Self::Bytes;

    type Bytes: ByteArray;
    type Radix16: Copy + AsRef<[i8]>;
    type Naf5: AsRef<[i8]>;

    fn is_zero(&self) -> Choice;

    fn ct_eq(&self, other: &Self) -> Choice;

    fn invert(self) -> Self;

    fn from_canonical(bytes: &Self::Bytes) -> Option<Self> {
        let non_zero = !is_zero(bytes.as_ref());
        let below = less_than(bytes.as_ref(), Self::ORDER.as_ref());
        (non_zero & below).to_bool().then(|| Self::from(*bytes))
    }

    fn as_radix_16(&self) -> Self::Radix16;

    fn non_adjacent_form_5(&self) -> Self::Naf5;

    fn as_signed_bits(&self) -> Self::Bytes;
}

pub(crate) trait Sealed {}

impl<const N: usize> Sealed for [u8; N] {}
