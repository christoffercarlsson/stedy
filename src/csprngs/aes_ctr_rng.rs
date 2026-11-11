use {
    crate::{
        Error,
        ciphers::{Aes128Ctr, Aes256Ctr},
        csprngs::StreamCipherRng,
        hashes::{Sha256, Sha384},
        traits::CryptoRng,
    },
    core::array::TryFromSliceError,
};

pub struct Aes128CtrRng(StreamCipherRng<Aes128Ctr, Sha256>);

impl Aes128CtrRng {
    pub fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.0.fill(bytes)
    }
}

#[cfg(feature = "getrandom")]
impl Aes128CtrRng {
    pub fn seed() -> Result<Self, Error> {
        StreamCipherRng::seed().map(Self)
    }

    pub fn reseed(&mut self) -> Result<(), Error> {
        self.0.reseed()
    }
}

impl From<&[u8; 64]> for Aes128CtrRng {
    fn from(seed: &[u8; 64]) -> Self {
        Self(StreamCipherRng::from(seed))
    }
}

impl From<[u8; 64]> for Aes128CtrRng {
    fn from(seed: [u8; 64]) -> Self {
        Self(StreamCipherRng::from(seed))
    }
}

impl TryFrom<&[u8]> for Aes128CtrRng {
    type Error = TryFromSliceError;

    fn try_from(seed: &[u8]) -> Result<Self, Self::Error> {
        StreamCipherRng::try_from(seed).map(Self)
    }
}

impl CryptoRng for Aes128CtrRng {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.0.fill(bytes)
    }
}

pub struct Aes256CtrRng(StreamCipherRng<Aes256Ctr, Sha384>);

impl Aes256CtrRng {
    pub fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.0.fill(bytes)
    }
}

#[cfg(feature = "getrandom")]
impl Aes256CtrRng {
    pub fn seed() -> Result<Self, Error> {
        StreamCipherRng::seed().map(Self)
    }

    pub fn reseed(&mut self) -> Result<(), Error> {
        self.0.reseed()
    }
}

impl From<&[u8; 96]> for Aes256CtrRng {
    fn from(seed: &[u8; 96]) -> Self {
        Self(StreamCipherRng::from(seed))
    }
}

impl From<[u8; 96]> for Aes256CtrRng {
    fn from(seed: [u8; 96]) -> Self {
        Self(StreamCipherRng::from(seed))
    }
}

impl TryFrom<&[u8]> for Aes256CtrRng {
    type Error = TryFromSliceError;

    fn try_from(seed: &[u8]) -> Result<Self, Self::Error> {
        StreamCipherRng::try_from(seed).map(Self)
    }
}

impl CryptoRng for Aes256CtrRng {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.0.fill(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128ctr_rng() {
        let seed = [0u8; 64];
        let mut rng = Aes128CtrRng::from(&seed);
        let mut output = [0u8; 48];
        rng.fill(&mut output).unwrap();
        assert_eq!(
            output,
            [
                172, 97, 163, 86, 247, 21, 103, 60, 183, 104, 17, 115, 138, 212, 25, 237, 181, 137,
                154, 62, 160, 187, 241, 192, 174, 76, 139, 104, 168, 179, 167, 102, 152, 220, 75,
                168, 23, 14, 121, 130, 88, 144, 17, 92, 201, 174, 68, 82
            ]
        );
    }

    #[test]
    fn test_aes256ctr_rng() {
        let seed = [0u8; 96];
        let mut rng = Aes256CtrRng::from(&seed);
        let mut output = [0u8; 48];
        rng.fill(&mut output).unwrap();
        assert_eq!(
            output,
            [
                8, 251, 245, 5, 176, 0, 241, 235, 248, 45, 128, 194, 75, 34, 51, 232, 166, 94, 30,
                186, 164, 209, 255, 226, 22, 251, 88, 159, 88, 80, 192, 201, 138, 207, 208, 6, 21,
                146, 65, 126, 69, 190, 132, 161, 159, 2, 179, 30
            ]
        );
    }
}
