use {
    crate::{
        traits::{ByteArray, Sealed, Wipe},
        utils::constant_time_eq,
    },
    core::{
        array::TryFromSliceError,
        fmt::{self, Debug, Formatter},
        ops::{Deref, Index, IndexMut, RangeFrom},
    },
};

#[derive(Clone)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    pub(crate) fn get_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> ByteArray for SecretBytes<N> {
    const SIZE: usize = N;

    fn new() -> Self {
        Self([0u8; N])
    }

    fn try_from_slice(slice: &[u8]) -> Result<Self, TryFromSliceError> {
        <[u8; N]>::try_from(slice).map(Self)
    }
}

impl<const N: usize> Sealed for SecretBytes<N> {}

impl<const N: usize> Wipe for SecretBytes<N> {
    fn wipe(&mut self) {
        self.0.wipe();
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

impl<const N: usize> Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(..)")
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl<const N: usize> PartialEq<[u8; N]> for SecretBytes<N> {
    fn eq(&self, other: &[u8; N]) -> bool {
        constant_time_eq(&self.0, other)
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

impl<const N: usize> Deref for SecretBytes<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for SecretBytes<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> TryFrom<&[u8]> for SecretBytes<N> {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_slice(slice)
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for SecretBytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> Index<usize> for SecretBytes<N> {
    type Output = u8;

    fn index(&self, index: usize) -> &u8 {
        &self.0[index]
    }
}

impl<const N: usize> IndexMut<usize> for SecretBytes<N> {
    fn index_mut(&mut self, index: usize) -> &mut u8 {
        &mut self.0[index]
    }
}

impl<const N: usize> Index<RangeFrom<usize>> for SecretBytes<N> {
    type Output = [u8];

    fn index(&self, index: RangeFrom<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl<const N: usize> IndexMut<RangeFrom<usize>> for SecretBytes<N> {
    fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut [u8] {
        &mut self.0[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_bytes() {
        let mut secret = SecretBytes::from([7u8; 8]);
        secret[0] = 1;
        assert_eq!(secret.as_ref(), [1, 7, 7, 7, 7, 7, 7, 7]);
        assert_eq!(&secret[6..], [7, 7]);
        assert_eq!(<SecretBytes<8> as ByteArray>::SIZE, 8);
        assert_eq!(SecretBytes::<4>::new().as_ref(), [0u8; 4]);
        assert!(SecretBytes::<4>::try_from_slice(&[1, 2, 3]).is_err());
        secret.wipe();
        assert_eq!(secret.as_ref(), [0u8; 8]);
    }

    #[test]
    fn test_secret_bytes_eq() {
        let secret = SecretBytes::from([1, 2, 3, 4]);
        assert_eq!(secret, SecretBytes::from([1, 2, 3, 4]));
        assert_ne!(secret, SecretBytes::from([1, 2, 3, 5]));
        assert_eq!(secret, [1, 2, 3, 4]);
        assert_ne!(secret, [0, 2, 3, 4]);
    }
}
