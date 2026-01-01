use crate::{
    blake2b::blake2b384,
    chacha::ChaCha20,
    traits::{Csprng, SeedableCsprng},
};

#[repr(C, align(4))]
pub struct Rng {
    cipher: ChaCha20,
}

impl Rng {
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

#[cfg(feature = "getrandom")]
impl Rng {
    pub fn seed() -> Option<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).ok()?;
        Some(Self::from(seed))
    }
}

impl From<&[u8; 32]> for Rng {
    fn from(value: &[u8; 32]) -> Self {
        Self::new(value)
    }
}

impl From<[u8; 32]> for Rng {
    fn from(value: [u8; 32]) -> Self {
        Self::from(&value)
    }
}

impl Csprng for Rng {
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

impl SeedableCsprng for Rng {
    const SEED_SIZE: usize = 32;

    type Seed = [u8; Self::SEED_SIZE];

    fn new(seed: &Self::Seed) -> Self {
        Self::new(seed)
    }
}

impl Rng {
    fn new(seed: &[u8; 32]) -> Self {
        let seed = blake2b384(seed);
        Self {
            cipher: ChaCha20::from(&seed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "getrandom")]
    #[test]
    fn test_getrandom_seed() {
        let mut rng = Rng::seed().unwrap();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        assert_ne!(bytes, [0u8; 32]);
        assert_ne!(
            bytes,
            [
                164, 57, 211, 237, 179, 104, 1, 234, 36, 204, 6, 111, 41, 227, 2, 30, 141, 242,
                229, 229, 5, 91, 53, 238, 8, 215, 139, 233, 41, 127, 255, 205
            ]
        );
    }

    #[test]
    fn test_next_u32() {
        let mut rng = Rng::from([0u8; 32]);
        let result = rng.next_u32();
        assert_eq!(result, 3990043044);
    }

    #[test]
    fn test_next_u64() {
        let mut rng = Rng::from([0u8; 32]);
        let result = rng.next_u64();
        assert_eq!(result, 16861873601850325412);
    }

    #[test]
    fn test_fill() {
        let mut rng = Rng::from([0u8; 32]);
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                164, 57, 211, 237, 179, 104, 1, 234, 36, 204, 6, 111, 41, 227, 2, 30, 141, 242,
                229, 229, 5, 91, 53, 238, 8, 215, 139, 233, 41, 127, 255, 205
            ]
        );
    }

    #[test]
    fn test_fill_multiple_blocks() {
        let mut rng = Rng::from([0u8; 32]);
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                164, 57, 211, 237, 179, 104, 1, 234, 36, 204, 6, 111, 41, 227, 2, 30, 141, 242,
                229, 229, 5, 91, 53, 238, 8, 215, 139, 233, 41, 127, 255, 205
            ]
        );
        let mut bytes = [0u8; 48];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                127, 181, 14, 92, 34, 12, 65, 56, 76, 209, 186, 114, 249, 17, 47, 3, 46, 125, 115,
                52, 126, 65, 165, 237, 179, 90, 164, 218, 244, 124, 136, 111, 44, 186, 244, 233,
                173, 251, 176, 117, 91, 193, 101, 144, 178, 171, 82, 52,
            ]
        );
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [152, 21, 147, 138, 78, 25, 116, 140, 83, 72, 177, 29, 175, 253, 169, 8],
        );
    }
}
