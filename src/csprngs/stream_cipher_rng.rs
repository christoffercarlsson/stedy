use {
    crate::{
        traits::{ByteArray, CryptoRng, Hasher, SeedableCryptoRng, SeekableStreamCipher},
        utils::Secret,
        Error,
    },
    core::{array::TryFromSliceError, marker::PhantomData},
};

pub struct StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
    cipher: C,
    produced: usize,
    _marker: PhantomData<H>,
}

impl<C, H> StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
    pub fn fill(&mut self, mut bytes: &mut [u8]) -> Result<(), Error> {
        while !bytes.is_empty() {
            let take = bytes.len().min(Self::REKEY_INTERVAL - self.produced);
            let (head, tail) = bytes.split_at_mut(take);
            self.cipher.apply_keystream(head)?;
            self.produced += take;
            if self.produced == Self::REKEY_INTERVAL {
                self.rekey()?;
            }
            bytes = tail;
        }
        Ok(())
    }
}

#[cfg(feature = "getrandom")]
impl<C, H> StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
    pub fn seed() -> Result<Self, Error> {
        let mut seed = Secret::from([H::Output::new(); 2]);
        for part in seed.get_mut() {
            getrandom::fill(part.as_mut()).map_err(|_| Error::Entropy)?;
        }
        Ok(Self::from_parts(seed.get().iter().map(AsRef::as_ref)))
    }

    pub fn reseed(&mut self) -> Result<(), Error> {
        *self = Self::seed()?;
        Ok(())
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
                Self::from_parts([&seed[..]])
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
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.fill(bytes)
    }
}

impl<C, H> SeedableCryptoRng for StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
}

impl<C, H> TryFrom<&[u8]> for StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
    type Error = TryFromSliceError;

    fn try_from(seed: &[u8]) -> Result<Self, Self::Error> {
        let (head, tail) = seed.split_at(seed.len().min(H::OUTPUT_SIZE));
        H::Output::try_from_slice(head)?;
        H::Output::try_from_slice(tail)?;
        Ok(Self::from_parts([head, tail]))
    }
}

impl<C, H> StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
    const REKEY_INTERVAL: usize = 1 << 16;

    fn from_parts<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let mut hasher = H::new();
        for part in parts {
            hasher.update(part);
        }
        let seed = hasher.finalize();
        Self {
            cipher: C::seed(&seed),
            produced: 0,
            _marker: PhantomData::<H>,
        }
    }

    fn rekey(&mut self) -> Result<(), Error> {
        let mut seed = Secret::from(C::Seed::new());
        self.cipher.apply_keystream(seed.get_mut().as_mut())?;
        self.cipher = C::seed(seed.get());
        self.produced = 0;
        Ok(())
    }
}
