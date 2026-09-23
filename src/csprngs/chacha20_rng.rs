use crate::{ciphers::ChaCha20, csprngs::StreamCipherRng, hashes::Blake2b384};

pub type ChaCha20Rng = StreamCipherRng<ChaCha20, Blake2b384>;

pub type Rng = ChaCha20Rng;

impl From<&[u8; 128]> for ChaCha20Rng {
    fn from(seed: &[u8; 128]) -> Self {
        Self::from(seed.as_slice())
    }
}

impl From<[u8; 128]> for ChaCha20Rng {
    fn from(seed: [u8; 128]) -> Self {
        Self::from(&seed)
    }
}

#[cfg(feature = "getrandom")]
impl ChaCha20Rng {
    pub fn seed() -> Self {
        let mut seed = [0u8; 128];
        getrandom::fill(&mut seed).expect(
            "ChaCha20Rng should be successfully seeded using the system's preferred entropy source",
        );
        Self::from(seed)
    }

    pub fn reseed(&mut self) {
        *self = Self::seed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "getrandom")]
    #[test]
    fn test_seed() {
        let mut rng = Rng::seed();
        let mut a = [0u8; 32];
        rng.fill(&mut a);
        assert_ne!(
            a,
            [
                253, 205, 139, 38, 230, 153, 90, 68, 159, 27, 68, 57, 5, 242, 232, 217, 162, 213,
                40, 127, 15, 170, 40, 184, 218, 178, 64, 246, 99, 149, 165, 24
            ]
        );
        rng.reseed();
        let mut b = [0u8; 32];
        rng.fill(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn test_next_u32() {
        let mut rng = Rng::from(&[0u8; 128]);
        let result = rng.next_u32();
        assert_eq!(result, 646696445);
    }

    #[test]
    fn test_next_u64() {
        let mut rng = Rng::from(&[0u8; 128]);
        let result = rng.next_u64();
        assert_eq!(result, 4925418356251282941);
    }

    #[test]
    fn test_fill() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                253, 205, 139, 38, 230, 153, 90, 68, 159, 27, 68, 57, 5, 242, 232, 217, 162, 213,
                40, 127, 15, 170, 40, 184, 218, 178, 64, 246, 99, 149, 165, 24
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
                253, 205, 139, 38, 230, 153, 90, 68, 159, 27, 68, 57, 5, 242, 232, 217, 162, 213,
                40, 127, 15, 170, 40, 184, 218, 178, 64, 246, 99, 149, 165, 24
            ]
        );
        let mut bytes = [0u8; 48];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                84, 192, 94, 242, 54, 147, 221, 40, 117, 117, 137, 97, 19, 106, 247, 183, 104, 109,
                164, 6, 13, 73, 26, 37, 221, 142, 213, 62, 140, 19, 162, 193, 76, 18, 254, 50, 63,
                26, 142, 145, 216, 22, 213, 220, 46, 154, 215, 91
            ]
        );
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [38, 121, 86, 133, 36, 75, 124, 121, 25, 5, 80, 35, 169, 175, 29, 102]
        );
    }
}
