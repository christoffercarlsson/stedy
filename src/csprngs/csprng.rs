use {
    crate::traits::{CryptoRng, Hasher, SeekableStreamCipher},
    core::marker::PhantomData,
};

pub struct Csprng<C: SeekableStreamCipher, H: Hasher<Output = C::Seed>> {
    cipher: C,
    _h: PhantomData<H>,
}

impl<C: SeekableStreamCipher, H: Hasher<Output = C::Seed>> Csprng<C, H> {
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

impl<C: SeekableStreamCipher, H: Hasher<Output = C::Seed>> CryptoRng for Csprng<C, H> {
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

impl<C: SeekableStreamCipher, H: Hasher<Output = C::Seed>> Csprng<C, H> {
    pub(crate) fn new(seed: &[u8]) -> Self {
        let mut hasher = H::new();
        hasher.update(seed);
        let seed = hasher.finalize();
        Self {
            cipher: C::seed(&seed),
            _h: PhantomData::<H>,
        }
    }
}
