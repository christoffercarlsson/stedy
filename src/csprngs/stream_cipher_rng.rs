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

    pub fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes);
        u64::from_le_bytes(bytes)
    }
}

impl<C, H> CryptoRng for StreamCipherRng<C, H>
where
    C: SeekableStreamCipher,
    H: Hasher<Output = C::Seed>,
{
    fn fill(&mut self, bytes: &mut [u8]) {
        self.fill(bytes);
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.next_u64()
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
        if seed.len() < H::OUTPUT_SIZE * 2 {
            return None;
        }
        let mut hasher = H::new();
        hasher.update(seed);
        let seed = hasher.finalize();
        Some(Self {
            cipher: C::seed(&seed),
            _marker: PhantomData::<H>,
        })
    }
}
