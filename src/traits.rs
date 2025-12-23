use core::ops::{Add, Mul, Neg, Sub};

#[allow(private_bounds)]
pub trait ByteArray: Sealed + Init + AsRef<[u8]> + AsMut<[u8]> + Copy {
    fn from_slice(slice: &[u8]) -> &Self;
}

pub trait Init {
    fn new() -> Self;
}

pub trait KeyInit {
    fn new(key: &[u8]) -> Self;
}

pub trait Digest {
    const OUTPUT_SIZE: usize;

    type Output: ByteArray;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> Self::Output;

    fn finalize_into(self, output: &mut Self::Output);
}

pub trait Hasher: Init + Digest {
    const BLOCK_SIZE: usize;

    type Block: ByteArray;
}

pub trait Mac: KeyInit + Digest {
    fn verify(self, code: &Self::Output) -> bool;
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
    fn seek(&mut self, counter: u32);
}

pub trait Csprng {
    fn fill(&mut self, bytes: &mut [u8]);

    fn next_u32(&mut self) -> u32;

    fn next_u64(&mut self) -> u64;
}

pub trait SeedableCsprng: Csprng {
    const SEED_SIZE: usize;

    type Seed: ByteArray;

    fn new(seed: &Self::Seed) -> Self;
}

pub trait FieldElement:
    Sized + Eq + Add<Output = Self> + Sub<Output = Self> + Mul<Output = Self> + Neg<Output = Self>
{
    const ZERO: Self;
    const ONE: Self;

    fn select(a: &Self, b: &Self, condition: u64) -> Self;

    fn square(self) -> Self;

    fn invert(self) -> Self;

    fn sqrt(self, b: Self) -> (Self, u64);
}

pub trait Scalar:
    Copy
    + From<Self::Bytes>
    + From<Self::WideBytes>
    + Into<Self::Bytes>
    + Add<Output = Self>
    + Mul<Output = Self>
{
    type Bytes: ByteArray;
    type WideBytes: ByteArray;

    fn concat(a: &Self::Bytes, b: &Self::Bytes) -> Self::WideBytes;

    fn split(bytes: &Self::WideBytes) -> (&Self::Bytes, &Self::Bytes);

    fn clamp(bytes: &mut Self::Bytes);
}

pub trait EdwardsPoint<F: FieldElement, S: Scalar>:
    Sized + Copy + Eq + Add<Output = Self> + Mul<S, Output = Self>
{
    const BASE_POINT: Self;
    const IDENTITY: Self;

    fn decompress(scalar: &S::Bytes) -> (Self, u64);

    fn compress(self) -> S::Bytes;
}

trait Sealed {}

impl<const N: usize> Sealed for [u8; N] {}

impl<const N: usize> Init for [u8; N] {
    fn new() -> Self {
        [0u8; N]
    }
}

impl<const N: usize> ByteArray for [u8; N] {
    fn from_slice(slice: &[u8]) -> &Self {
        match <&Self>::try_from(slice) {
            Ok(r) => r,
            Err(_) => &[0u8; N],
        }
    }
}
