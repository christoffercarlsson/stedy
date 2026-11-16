use {
    crate::traits::{ByteArray, Sealed},
    core::array::TryFromSliceError,
};

impl<const N: usize> ByteArray for [u8; N] {
    const SIZE: usize = N;

    fn new() -> Self {
        [0u8; N]
    }

    fn try_from_slice(slice: &[u8]) -> Result<Self, TryFromSliceError> {
        Self::try_from(slice)
    }
}

impl<const N: usize> Sealed for [u8; N] {}
