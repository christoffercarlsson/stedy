use {
    crate::utils::wipe,
    core::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub},
};

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

pub trait Curve {
    type Point;
    type PointBytes: ByteArray;
    type Scalar;
    type ScalarBytes: ByteArray;

    fn generate_scalar(rng: &mut impl CryptoRng) -> Self::Scalar {
        loop {
            let mut bytes = Self::ScalarBytes::new();
            rng.fill(bytes.as_mut());
            let result = Self::scalar_from_bytes(&bytes);
            wipe(bytes.as_mut());
            if let Some(scalar) = result {
                return scalar;
            }
        }
    }

    fn scalar_mult_base(scalar: &Self::Scalar) -> Self::Point {
        Self::scalar_mult(scalar, &Self::base_point())
            .expect("scalar_mult_base is always a valid point")
    }

    fn base_point() -> Self::Point;

    fn point_from_bytes(bytes: &Self::PointBytes) -> Option<Self::Point>;

    fn point_to_bytes(point: &Self::Point) -> Self::PointBytes;

    fn scalar_from_bytes(bytes: &Self::ScalarBytes) -> Option<Self::Scalar>;

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes;

    fn scalar_mult(scalar: &Self::Scalar, point: &Self::Point) -> Option<Self::Point>;
}

pub trait Digest {
    const OUTPUT_SIZE: usize;

    type Output: ByteArray;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> Self::Output;

    fn finalize_into(self, output: &mut Self::Output);
}

pub trait EdwardsPoint<S: Scalar>:
    Sized + Copy + Eq + Add<Self, Output = Self> + Mul<S, Output = Self>
{
    const BASE_POINT: Self;
    const IDENTITY: Self;

    type Bytes: ByteArray;

    fn decompress(bytes: &Self::Bytes) -> (Self, u64);

    fn compress(self) -> Self::Bytes;

    #[allow(non_snake_case)]
    fn vartime_double_base(a: &S, A: Self, b: &S) -> Self;
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
        Self::from_slice_checked(slice).expect("Slice size matches array size")
    }

    fn from_slice_checked(slice: &[u8]) -> Option<&Self> {
        <&Self>::try_from(slice).ok()
    }

    fn from_slice_mut_checked(slice: &mut [u8]) -> Option<&mut Self> {
        <&mut Self>::try_from(slice).ok()
    }
}
