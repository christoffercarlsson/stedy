#![allow(dead_code)]
use {
    crate::utils::{is_zero, less_than, wipe},
    core::ops::{
        Add, AddAssign, Div, DivAssign, Index, IndexMut, Mul, MulAssign, Neg, RangeFrom, Sub,
        SubAssign,
    },
};

pub trait Authenticator<C: SeekableStreamCipher> {
    type Output;

    fn new(cipher: &mut C) -> Self;

    fn tag(self, ciphertext: &[u8], aad: Option<&[u8]>) -> Self::Output;

    fn verify(self, ciphertext: &[u8], aad: Option<&[u8]>, tag: &Self::Output) -> bool;
}

#[allow(private_bounds)]
pub trait ByteArray:
    Copy
    + Sized
    + Ord
    + AsRef<[u8]>
    + AsMut<[u8]>
    + Index<usize, Output = u8>
    + Index<RangeFrom<usize>, Output = [u8]>
    + IndexMut<usize, Output = u8>
    + IndexMut<RangeFrom<usize>, Output = [u8]>
    + Sealed
{
    const SIZE: usize;

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

pub trait EdwardsParams<F: FieldElement> {
    const D: F;
    const D2: F;
    const BASE_POINT_X: F;
    const BASE_POINT_Y: F;
    const BASE_POINT_T: F;
}

pub trait EdwardsScalar:
    Sized
    + Copy
    + From<Self::Bytes>
    + From<Self::WideBytes>
    + Into<Self::Bytes>
    + Add<Self, Output = Self>
    + AddAssign
    + Mul<Self, Output = Self>
    + MulAssign
    + Neg<Output = Self>
{
    type Bytes: ByteArray;
    type WideBytes: ByteArray;
    type Radix16: AsRef<[i8]>;
    type Naf5: AsRef<[i8]>;

    fn split(bytes: &Self::WideBytes) -> (&Self::Bytes, &Self::Bytes);

    fn clamp(bytes: &mut Self::Bytes);

    fn as_radix_16(&self) -> Self::Radix16;

    fn non_adjacent_form_5(&self) -> Self::Naf5;
}

pub trait EllipticCurve {
    const BASE_POINT: Self::Point;

    type Point;
    type Scalar;
    type PointBytes: ByteArray;
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
        Self::scalar_mult(scalar, &Self::BASE_POINT)
            .expect("scalar_mult_base always produce valid points")
    }

    fn point_from_bytes(bytes: &Self::PointBytes) -> Option<Self::Point>;

    fn point_to_bytes(point: &Self::Point) -> Self::PointBytes;

    fn scalar_from_bytes(bytes: &Self::ScalarBytes) -> Option<Self::Scalar>;

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes;

    fn scalar_mult(scalar: &Self::Scalar, point: &Self::Point) -> Option<Self::Point>;
}

pub trait EcdsaCurve: EllipticCurve {}

pub trait FieldElement:
    Sized
    + Copy
    + Eq
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + MulAssign
    + Div<Output = Self>
    + DivAssign
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

pub trait MontgomeryParams<const LIMBS: usize>: Copy + Clone {
    const BITS: u32;
    const TOP_BITS: u32;
    const MOD: [u64; LIMBS];
    const R: [u64; LIMBS];
    const R2: [u64; LIMBS];
    const N0: u64;
}

pub trait Prf: KeyInit + Digest {}

pub trait StreamCipher {
    const KEY_SIZE: usize;
    const NONCE_SIZE: usize;

    type Key: ByteArray;
    type Nonce: ByteArray;

    fn new(key: &Self::Key, nonce: &Self::Nonce) -> Self;

    fn apply_keystream(&mut self, message: &mut [u8]);
}

pub trait SeedableCryptoRng: CryptoRng + Sized {
    fn new(seed: &[u8]) -> Self;

    fn reseed(&mut self, seed: &[u8]) {
        *self = Self::new(seed);
    }
}

pub trait SeekableStreamCipher: StreamCipher {
    const SEED_SIZE: usize;

    type Seed: ByteArray;

    fn seed(seed: &Self::Seed) -> Self;

    fn seek(&mut self, counter: u32);
}

pub trait WeierstrassParams<F: FieldElement> {
    const A: F;
    const B: F;
    const BASE_POINT_X: F;
    const BASE_POINT_Y: F;

    type PointBytes: ByteArray;
}

pub trait WeierstrassScalar:
    Sized
    + Copy
    + PartialEq
    + Eq
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
    type Radix16: AsRef<[i8]>;
    type Naf5: AsRef<[i8]>;

    fn is_zero(&self) -> bool;

    fn invert(self) -> Self;

    fn from_canonical(bytes: &Self::Bytes) -> Option<Self> {
        let non_zero = !is_zero(bytes.as_ref());
        let below = less_than(bytes.as_ref(), Self::ORDER.as_ref());
        (non_zero & below).then(|| Self::from(*bytes))
    }

    fn as_radix_16(&self) -> Self::Radix16;

    fn non_adjacent_form_5(&self) -> Self::Naf5;
}

trait Sealed {}

impl<const N: usize> Sealed for [u8; N] {}

impl<const N: usize> ByteArray for [u8; N] {
    const SIZE: usize = N;

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
