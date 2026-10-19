#![allow(dead_code)]
use {
    super::Sealed,
    crate::{
        Error,
        utils::{Choice, Secret, is_zero},
    },
    core::{
        array::TryFromSliceError,
        ops::{Add, AddAssign, Index, IndexMut, Mul, MulAssign, Neg, RangeFrom, Sub, SubAssign},
    },
};

pub trait Authenticator<C: SeekableStreamCipher> {
    const ACCEPTS_AAD: bool = true;

    type Output;

    fn new(cipher: &mut C) -> Self;

    fn tag(self, ciphertext: &[u8], aad: Option<&[u8]>) -> Self::Output;

    fn verify(self, ciphertext: &[u8], aad: Option<&[u8]>, tag: &Self::Output) -> bool;
}

#[allow(private_bounds)]
pub trait ByteArray:
    Copy
    + Sized
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

    fn from_slice(slice: &[u8]) -> Self {
        Self::try_from_slice(slice).expect("the given slice is exactly ByteArray::SIZE bytes")
    }

    fn try_from_slice(slice: &[u8]) -> Result<Self, TryFromSliceError>;
}

pub trait CryptoRng {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error>;
}

pub trait Digest {
    const OUTPUT_SIZE: usize;

    type Output: ByteArray;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> Self::Output;

    fn finalize_into(self, output: &mut [u8]);
}

pub trait EdwardsParams<F: FieldElement> {
    const A: i8;
    const D: F;
    const D2: F;
    const DOMAIN: &'static [u8];
    const DOMAIN_PURE: bool;
    const BASE_POINT_X: F;
    const BASE_POINT_Y: F;
    const BASE_POINT_T: F;
    const BASE_COMB_LOW: [[F; 3]; 8];
    const BASE_COMB_HIGH: [[F; 3]; 8];
}

pub trait EllipticCurve {
    const BASE_POINT: Self::Point;

    type Point;
    type Scalar;
    type PointBytes: ByteArray;
    type ScalarBytes: ByteArray;
    type SharedSecretBytes: ByteArray;

    fn generate_scalar(rng: &mut impl CryptoRng) -> Result<Self::Scalar, Error> {
        loop {
            let mut bytes = Secret::from(Self::ScalarBytes::new());
            rng.fill(bytes.get_mut().as_mut())?;
            if let Ok(scalar) = Self::scalar_from_bytes(bytes.get()) {
                return Ok(scalar);
            }
        }
    }

    fn scalar_mult_base(scalar: &Self::Scalar) -> Self::Point;

    fn point_from_bytes(bytes: &Self::PointBytes) -> Result<Self::Point, Error>;

    fn point_to_bytes(point: &Self::Point) -> Self::PointBytes;

    fn shared_secret_bytes(point: &Self::Point) -> Self::SharedSecretBytes;

    fn scalar_from_bytes(bytes: &Self::ScalarBytes) -> Result<Self::Scalar, Error>;

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes;

    fn scalar_mult(scalar: &Self::Scalar, point: &Self::Point) -> Result<Self::Point, Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    BigEndian,
    LittleEndian,
}

pub trait FieldElement:
    Sized
    + Copy
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + MulAssign
    + Neg<Output = Self>
    + From<Self::Bytes>
    + Into<Self::Bytes>
{
    const CAPACITY: usize;
    const BYTE_ORDER: ByteOrder;

    const ZERO: Self;
    const ONE: Self;

    type Bytes: ByteArray;

    fn swap(a: &mut Self, b: &mut Self, condition: Choice) {
        let swapped = Self::select(a, b, condition);
        *b = Self::select(b, a, condition);
        *a = swapped;
    }

    fn select(a: &Self, b: &Self, condition: Choice) -> Self;

    fn assign(&mut self, other: &Self, condition: Choice) {
        *self = Self::select(self, other, condition);
    }

    fn ct_eq(&self, other: &Self) -> Choice {
        let difference: Self::Bytes = (*self - *other).into();
        is_zero(difference.as_ref())
    }

    fn square(self) -> Self {
        self * self
    }

    fn square2(self) -> Self {
        let square = self.square();
        square + square
    }

    fn double_value(self) -> Self {
        self + self
    }

    fn invert(self) -> Self;

    fn sqrt(self, b: Self) -> (Self, Choice);

    fn from_u32(value: u32) -> Self {
        let mut bytes = Self::Bytes::new();
        let size = Self::Bytes::SIZE.min(4);
        match Self::BYTE_ORDER {
            ByteOrder::BigEndian => bytes.as_mut()[Self::Bytes::SIZE - size..]
                .copy_from_slice(&value.to_be_bytes()[4 - size..]),
            ByteOrder::LittleEndian => {
                bytes.as_mut()[..size].copy_from_slice(&value.to_le_bytes()[..size])
            }
        }
        Self::from(bytes)
    }
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
    fn new(key: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
}

pub trait Mac: KeyInit + Digest {
    fn verify(self, code: &Self::Output) -> Result<(), Error>;
}

pub trait Prf: KeyInit + Digest {}

pub trait StreamCipher {
    const KEY_SIZE: usize;
    const NONCE_SIZE: usize;

    type Key: ByteArray;
    type Nonce: ByteArray;

    fn new(key: &Self::Key, nonce: &Self::Nonce) -> Self;

    fn apply_keystream(&mut self, message: &mut [u8]) -> Result<(), Error>;
}

pub trait SeedableCryptoRng:
    CryptoRng + Sized + for<'a> TryFrom<&'a [u8], Error = TryFromSliceError>
{
    fn reseed(&mut self, seed: &[u8]) -> Result<(), TryFromSliceError> {
        *self = Self::try_from(seed)?;
        Ok(())
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
    const BASE_NAF: [[F; 2]; 8];
    const BASE_COMB_LOW: [[F; 2]; 8];
    const BASE_COMB_HIGH: [[F; 2]; 8];

    type PointBytes: ByteArray;
}

pub trait Xof: Init {
    type Reader: XofReader;

    fn digest(message: &[u8], output: &mut [u8]);

    fn update(&mut self, message: &[u8]);

    fn finalize_into(self, output: &mut [u8]);

    fn finalize_xof(self) -> Self::Reader;
}

pub trait XofReader {
    fn read(&mut self, output: &mut [u8]);
}

impl<const N: usize> ByteArray for [u8; N] {
    const SIZE: usize = N;

    fn new() -> Self {
        [0u8; N]
    }

    fn try_from_slice(slice: &[u8]) -> Result<Self, TryFromSliceError> {
        Self::try_from(slice)
    }
}
