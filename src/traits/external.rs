use {
    super::Sealed,
    crate::Error,
    core::{
        array::TryFromSliceError,
        ops::{Index, IndexMut, RangeFrom},
    },
};

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

#[cfg(feature = "hazmat")]
pub trait FieldArithmetic {
    type Bytes: ByteArray;

    fn add(a: &Self::Bytes, b: &Self::Bytes) -> Self::Bytes;

    fn sub(a: &Self::Bytes, b: &Self::Bytes) -> Self::Bytes;

    fn mul(a: &Self::Bytes, b: &Self::Bytes) -> Self::Bytes;

    fn square(a: &Self::Bytes) -> Self::Bytes {
        Self::mul(a, a)
    }
}

pub trait Hasher: Sized {
    const BLOCK_SIZE: usize;
    const OUTPUT_SIZE: usize;

    type Block: ByteArray;
    type Output: ByteArray;

    fn new() -> Self;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> Self::Output;

    fn finalize_into(self, output: &mut [u8]);

    fn digest(message: &[u8]) -> Self::Output;
}

pub trait KeccakPermutation {
    fn permute(lanes: &mut [u64; 25]);
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
