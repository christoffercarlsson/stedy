#[cfg(feature = "getrandom")]
use crate::{traits::ByteArray, utils::Secret};
use {
    crate::traits::{CryptoRng, Hasher, SeedableCryptoRng, SeekableStreamCipher},
    core::marker::PhantomData,
};

pub struct StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
    cipher: C,
    _marker: PhantomData<H>,
}

impl<C, H> StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
    pub fn new(seed: &[u8]) -> Self {
        Self::init(seed).expect("Provided seed is large enough for StreamCipherRng")
    }

    pub fn fill(&mut self, bytes: &mut [u8]) {
        self.cipher.apply_keystream(bytes);
    }
}

#[cfg(feature = "getrandom")]
impl<C, H> StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
    pub fn seed() -> Self {
        let mut seed = Secret::from([H::Output::new(); 2]);
        for part in seed.get_mut() {
            getrandom::fill(part.as_mut()).expect(
                "StreamCipherRng should be successfully seeded using the system's preferred entropy source",
            );
        }
        Self::from_parts(seed.get().iter().map(AsRef::as_ref))
    }

    pub fn reseed(&mut self) {
        *self = Self::seed();
    }
}

macro_rules! impl_from_seed {
    ($seed:literal, $output:literal) => {
        impl<C, H> From<&[u8; $seed]> for StreamCipherRng<C, H>
        where
            C: SeekableStreamCipher<Seed = [u8; $output]>,
            H: Hasher<Output = [u8; $output]>,
        {
            fn from(seed: &[u8; $seed]) -> Self {
                Self::new(seed)
            }
        }

        impl<C, H> From<[u8; $seed]> for StreamCipherRng<C, H>
        where
            C: SeekableStreamCipher<Seed = [u8; $output]>,
            H: Hasher<Output = [u8; $output]>,
        {
            fn from(seed: [u8; $seed]) -> Self {
                Self::from(&seed)
            }
        }
    };
}

impl_from_seed!(64, 32);
impl_from_seed!(96, 48);
impl_from_seed!(128, 64);

impl<C, H> CryptoRng for StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
    fn fill(&mut self, bytes: &mut [u8]) {
        self.fill(bytes);
    }
}

impl<C, H> SeedableCryptoRng for StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
    fn new(seed: &[u8]) -> Self {
        Self::new(seed)
    }
}

impl<C, H> From<&[u8]> for StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
    fn from(seed: &[u8]) -> Self {
        Self::new(seed)
    }
}

impl<C, H> StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
    fn init(seed: &[u8]) -> Option<Self> {
        (seed.len() >= H::OUTPUT_SIZE * 2).then(|| Self::from_parts([seed]))
    }

    fn from_parts<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let mut hasher = H::new();
        for part in parts {
            hasher.update(part);
        }
        let seed = hasher.finalize();
        Self {
            cipher: C::seed(&seed),
            _marker: PhantomData::<H>,
        }
    }
}
