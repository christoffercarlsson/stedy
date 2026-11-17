use {
    super::{Sealed, Wipe},
    crate::{Error, utils::SecretBytes},
    core::{
        array::TryFromSliceError,
        ops::{Index, IndexMut, RangeFrom},
    },
};

pub trait Aead: Sealed {
    const ID: u16;

    type Key: ByteArray;
    type Nonce: ByteArray;
    type Tag: ByteArray;

    fn encrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: Option<&[u8]>,
        message: &mut [u8],
    ) -> Result<Self::Tag, Error>;

    fn decrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        aad: Option<&[u8]>,
        message: &mut [u8],
        tag: &Self::Tag,
    ) -> Result<(), Error>;

    fn generate_key(rng: &mut impl CryptoRng) -> Result<Self::Key, Error>;

    fn increment_nonce(nonce: &mut Self::Nonce) -> Result<(), Error>;
}

pub trait ByteArray:
    Clone
    + Sized
    + AsRef<[u8]>
    + AsMut<[u8]>
    + Index<usize, Output = u8>
    + Index<RangeFrom<usize>, Output = [u8]>
    + IndexMut<usize, Output = u8>
    + IndexMut<RangeFrom<usize>, Output = [u8]>
    + Sealed
    + Wipe
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

    fn next_u32(&mut self) -> Result<u32, Error> {
        let mut bytes = SecretBytes::new();
        self.fill(bytes.as_mut())?;
        Ok(u32::from_le_bytes(*bytes))
    }

    fn next_u64(&mut self) -> Result<u64, Error> {
        let mut bytes = SecretBytes::new();
        self.fill(bytes.as_mut())?;
        Ok(u64::from_le_bytes(*bytes))
    }
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

pub trait HashFunction: Clone + Hasher + Sealed {
    const ID: u16;
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

pub trait Kdf: Sealed {
    const ID: u16;

    fn derive(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output: &mut [u8],
    ) -> Result<(), Error>;
}

pub trait KeccakPermutation {
    fn permute(lanes: &mut [u64; 25]);
}

pub trait Kem: Sealed {
    const ID: u16;

    type Seed: ByteArray;
    type PrivateKey: ByteArray;
    type PublicKey: ByteArray;
    type Ciphertext: ByteArray;
    type SharedSecret: ByteArray;

    fn generate_key_pair(
        rng: &mut impl CryptoRng,
    ) -> Result<(Self::PrivateKey, Self::PublicKey), Error>;

    fn key_pair(seed: &Self::Seed) -> (Self::PrivateKey, Self::PublicKey);

    fn public_key(private_key: &Self::PrivateKey) -> Self::PublicKey;

    fn encapsulate(
        public_key: &Self::PublicKey,
        rng: &mut impl CryptoRng,
    ) -> Result<(Self::SharedSecret, Self::Ciphertext), Error>;

    fn decapsulate(
        private_key: &Self::PrivateKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, Error>;
}

pub trait KeyExchange: Sealed {
    const ID: u16;

    type PrivateKey: ByteArray;
    type PublicKey: ByteArray;
    type SharedSecret: ByteArray;

    fn generate_key_pair(
        rng: &mut impl CryptoRng,
    ) -> Result<(Self::PrivateKey, Self::PublicKey), Error>;

    fn public_key(private_key: &Self::PrivateKey) -> Result<Self::PublicKey, Error>;

    fn key_exchange(
        private_key: &Self::PrivateKey,
        public_key: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, Error>;
}

pub trait Mac: Clone + Sealed {
    const ID: u16;

    type Code: ByteArray;

    fn new(key: &[u8]) -> Self;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> Self::Code;

    fn verify(self, code: &Self::Code) -> Result<(), Error>;
}

pub trait SignatureScheme: Sealed {
    const ID: u16;

    type PrivateKey: ByteArray;
    type PublicKey: ByteArray;
    type Signature: ByteArray;

    fn generate_key_pair(
        rng: &mut impl CryptoRng,
    ) -> Result<(Self::PrivateKey, Self::PublicKey), Error>;

    fn public_key(private_key: &Self::PrivateKey) -> Result<Self::PublicKey, Error>;

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Self::Signature, Error>;

    fn verify(
        message: &[u8],
        public_key: &Self::PublicKey,
        signature: &Self::Signature,
    ) -> Result<(), Error>;
}
