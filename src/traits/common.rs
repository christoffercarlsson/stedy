use core::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub};

pub trait Authenticator<C: SeekableStreamCipher> {
    type Output;

    fn new(cipher: &mut C) -> Self;

    fn tag(self, ciphertext: &[u8], aad: Option<&[u8]>) -> Self::Output;

    fn verify(self, ciphertext: &[u8], aad: Option<&[u8]>, tag: &Self::Output) -> bool;
}

#[allow(private_bounds)]
pub trait ByteArray: Copy + Ord + AsRef<[u8]> + AsMut<[u8]> + Sealed {
    fn new() -> Self;

    fn from_slice(slice: &[u8]) -> &Self;

    fn from_slice_checked(slice: &[u8]) -> Option<&Self>;

    fn from_slice_mut_checked(slice: &mut [u8]) -> Option<&mut Self>;
}

pub trait CryptoRng {
    fn fill(&mut self, bytes: &mut [u8]);

    fn next_u32(&mut self) -> u32;

    fn next_u64(&mut self) -> u64;
}

pub trait Digest {
    const OUTPUT_SIZE: usize;

    type Output: ByteArray;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> Self::Output;

    fn finalize_into(self, output: &mut Self::Output);
}

pub trait EdwardsPoint<F: FieldElement, S: Scalar>:
    Sized + Copy + Eq + Add<Self, Output = Self> + Mul<S, Output = Self>
{
    const BASE_POINT: Self;
    const IDENTITY: Self;

    fn decompress(scalar: &S::Bytes) -> (Self, u64);

    fn compress(self) -> S::Bytes;

    fn vartime_double_base(a: &S, p: Self, b: &S) -> Self;
}

pub trait FieldElement:
    Sized
    + Copy
    + Eq
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + Mul<Output = Self>
    + MulAssign
    + Div<Output = Self>
    + Neg<Output = Self>
    + From<Self::Bytes>
    + Into<Self::Bytes>
    + From<u32>
{
    const ZERO: Self;
    const ONE: Self;

    type Bytes: ByteArray;

    fn swap(a: &mut Self, b: &mut Self, condition: u64);

    fn select(a: &Self, b: &Self, condition: u64) -> Self;

    fn square(self) -> Self;

    fn invert(self) -> Self;

    fn sqrt(self, b: Self) -> (Self, u64);
}

pub trait Hasher: Init + Digest {
    const BLOCK_SIZE: usize;

    type Block: ByteArray;

    fn digest(message: &[u8]) -> Self::Output;
}

pub trait Init {
    fn new() -> Self;
}

pub trait KeyInit {
    fn new(key: &[u8]) -> Self;
}

pub trait Mac: KeyInit + Digest {
    fn verify(self, code: &Self::Output) -> bool;
}

pub trait Prf: KeyInit + Digest {}

pub trait Scalar:
    Copy
    + From<Self::Bytes>
    + From<Self::WideBytes>
    + Into<Self::Bytes>
    + Add<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Neg<Output = Self>
{
    type Bytes: ByteArray;
    type WideBytes: ByteArray;

    fn concat(a: &Self::Bytes, b: &Self::Bytes) -> Self::WideBytes;

    fn split(bytes: &Self::WideBytes) -> (&Self::Bytes, &Self::Bytes);

    fn clamp(bytes: &mut Self::Bytes);
}

pub trait StreamCipher {
    const KEY_SIZE: usize;
    const NONCE_SIZE: usize;

    type Key: ByteArray;
    type Nonce: ByteArray;

    fn new(key: &Self::Key, nonce: &Self::Nonce) -> Self;

    fn apply_keystream(&mut self, message: &mut [u8]);
}

pub trait SeekableStreamCipher: StreamCipher {
    const SEED_SIZE: usize;

    type Seed: ByteArray;

    fn seed(seed: &Self::Seed) -> Self;

    fn seek(&mut self, counter: u32);
}

trait Sealed {}

impl<const N: usize> Sealed for [u8; N] {}

impl<const N: usize> ByteArray for [u8; N] {
    fn new() -> Self {
        [0u8; N]
    }

    fn from_slice(slice: &[u8]) -> &Self {
        Self::from_slice_checked(slice).unwrap_or(&[0u8; N])
    }

    fn from_slice_checked(slice: &[u8]) -> Option<&Self> {
        <&Self>::try_from(slice).ok()
    }

    fn from_slice_mut_checked(slice: &mut [u8]) -> Option<&mut Self> {
        <&mut Self>::try_from(slice).ok()
    }
}
