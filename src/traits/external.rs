#![allow(dead_code)]
use {
    super::Sealed,
    crate::Error,
    core::{
        array::TryFromSliceError,
        ops::{Index, IndexMut, RangeFrom},
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

pub trait FieldArithmetic {
    type Bytes: ByteArray;

    fn add(a: &Self::Bytes, b: &Self::Bytes) -> Self::Bytes;

    fn sub(a: &Self::Bytes, b: &Self::Bytes) -> Self::Bytes;

    fn mul(a: &Self::Bytes, b: &Self::Bytes) -> Self::Bytes;

    fn square(a: &Self::Bytes) -> Self::Bytes {
        Self::mul(a, a)
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

pub trait KeccakPermutation {
    fn permute(lanes: &mut [u64; 25]);
}

pub trait KeyInit {
    fn new(key: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
}

pub trait Mac: KeyInit + Digest {
    fn verify(self, code: &Self::Output) -> Result<(), Error>;
}

pub trait MlDsaArithmetic {
    fn ntt(w: &mut [i32; 256]);

    fn inverse_ntt(w: &mut [i32; 256]);

    fn multiply_ntt(a: &[i32; 256], b: &[i32; 256], w: &mut [i32; 256]);
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
