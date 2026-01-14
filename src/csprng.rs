use {
    crate::{
        blake2b::Blake2b384,
        chacha::ChaCha20,
        traits::{CryptoRng, Hasher, SeedableRng, SeekableStreamCipher},
    },
    core::marker::PhantomData,
};

pub struct Csprng<C: SeekableStreamCipher, H: Hasher<Output = C::Seed>> {
    cipher: C,
    _h: PhantomData<H>,
}

impl<C: SeekableStreamCipher, H: Hasher<Output = C::Seed>> Csprng<C, H> {
    pub fn new(seed: &[u8]) -> Option<Self> {
        if seed.len() < H::OUTPUT_SIZE * 2 {
            return None;
        }
        let mut hasher = H::new();
        hasher.update(seed);
        let seed = hasher.finalize();
        Some(Self {
            cipher: C::seed(&seed),
            _h: PhantomData::<H>,
        })
    }

    pub fn seed(&mut self, seed: &[u8]) -> bool {
        if let Some(rng) = Self::new(seed) {
            *self = rng;
            true
        } else {
            false
        }
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

impl<C: SeekableStreamCipher, H: Hasher<Output = C::Seed>> SeedableRng for Csprng<C, H> {
    fn new(seed: &[u8]) -> Option<Self> {
        Self::new(seed)
    }

    fn seed(&mut self, seed: &[u8]) -> bool {
        self.seed(seed)
    }
}

pub type Rng = Csprng<ChaCha20, Blake2b384>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_u32() {
        let mut rng = Rng::new(&[0u8; 96]).unwrap();
        let result = rng.next_u32();
        assert_eq!(result, 1987994301);
    }

    #[test]
    fn test_next_u64() {
        let mut rng = Rng::new(&[0u8; 96]).unwrap();
        let result = rng.next_u64();
        assert_eq!(result, 7751686179014992573);
    }

    #[test]
    fn test_fill() {
        let mut rng = Rng::new(&[0u8; 96]).unwrap();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102,
                238, 246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 204
            ]
        );
    }

    #[test]
    fn test_fill_multiple_blocks() {
        let mut rng = Rng::new(&[0u8; 96]).unwrap();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102,
                238, 246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 204
            ]
        );
        let mut bytes = [0u8; 48];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                202, 29, 227, 98, 39, 63, 218, 245, 127, 170, 158, 94, 212, 115, 2, 22, 109, 212,
                235, 42, 215, 1, 120, 200, 5, 161, 173, 162, 48, 153, 5, 228, 51, 185, 144, 5, 108,
                180, 103, 227, 33, 249, 180, 55, 133, 138, 84, 78
            ]
        );
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [248, 192, 49, 168, 83, 96, 159, 150, 163, 210, 249, 205, 252, 103, 187, 90]
        );
    }
}
