use {
    crate::{
        blake2b::Blake2b384,
        chacha::ChaCha20,
        traits::{CryptoRng, Hasher, SeekableStreamCipher},
    },
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
    fn new(seed: &[u8]) -> Self {
        let mut hasher = H::new();
        hasher.update(seed);
        let seed = hasher.finalize();
        Self {
            cipher: C::seed(&seed),
            _h: PhantomData::<H>,
        }
    }
}

pub type Rng = Csprng<ChaCha20, Blake2b384>;

impl From<&[u8; 128]> for Rng {
    fn from(seed: &[u8; 128]) -> Self {
        Self::new(seed)
    }
}

impl From<[u8; 128]> for Rng {
    fn from(seed: [u8; 128]) -> Self {
        Self::from(&seed)
    }
}

#[cfg(feature = "getrandom")]
impl Rng {
    pub fn seed() -> Self {
        let mut seed = [0u8; 128];
        getrandom::fill(&mut seed)
            .expect("CSPRNG should be seeded using the system's preferred entropy source");
        Self::from(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "getrandom")]
    #[test]
    fn test_seed() {
        let mut rng = Rng::seed();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        assert_ne!(
            bytes,
            [
                89, 151, 243, 239, 17, 196, 251, 133, 30, 56, 89, 220, 74, 144, 209, 105, 150, 125,
                139, 44, 132, 127, 191, 13, 64, 39, 240, 246, 10, 240, 124, 104
            ]
        );
    }

    #[test]
    fn test_next_u32() {
        let mut rng = Rng::from(&[0u8; 128]);
        let result = rng.next_u32();
        assert_eq!(result, 4025718617);
    }

    #[test]
    fn test_next_u64() {
        let mut rng = Rng::from(&[0u8; 128]);
        let result = rng.next_u64();
        assert_eq!(result, 9654525807517996889);
    }

    #[test]
    fn test_fill() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                89, 151, 243, 239, 17, 196, 251, 133, 30, 56, 89, 220, 74, 144, 209, 105, 150, 125,
                139, 44, 132, 127, 191, 13, 64, 39, 240, 246, 10, 240, 124, 104
            ]
        );
    }

    #[test]
    fn test_fill_multiple_blocks() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                89, 151, 243, 239, 17, 196, 251, 133, 30, 56, 89, 220, 74, 144, 209, 105, 150, 125,
                139, 44, 132, 127, 191, 13, 64, 39, 240, 246, 10, 240, 124, 104
            ]
        );
        let mut bytes = [0u8; 48];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                108, 146, 119, 105, 4, 4, 214, 165, 18, 40, 155, 173, 139, 34, 253, 223, 121, 58,
                96, 51, 144, 140, 216, 89, 33, 178, 169, 152, 2, 2, 92, 0, 14, 210, 107, 149, 175,
                222, 110, 64, 71, 138, 111, 46, 228, 249, 36, 115
            ]
        );
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [207, 95, 167, 198, 254, 54, 36, 42, 174, 255, 53, 160, 250, 74, 236, 10]
        );
    }
}
