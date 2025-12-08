use crate::chacha::ChaCha20;

pub struct Rng {
    cipher: ChaCha20,
}

impl Rng {
    pub fn new(seed: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20::from(seed),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_u32() {
        let seed = [0u8; 32];
        let mut rng = Rng::from(seed);
        let result = rng.next_u32();
        assert_eq!(result, 2917185654);
    }

    #[test]
    fn test_next_u64() {
        let seed = [0u8; 32];
        let mut rng = Rng::from(seed);
        let result = rng.next_u64();
        assert_eq!(result, 10393729187455219830);
    }

    #[test]
    fn test_fill() {
        let seed = [0u8; 32];
        let mut rng = Rng::from(seed);
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189,
                210, 25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199,
            ]
        );
    }

    #[test]
    fn test_fill_multiple_blocks() {
        let seed = [0u8; 32];
        let mut rng = Rng::from(seed);
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189,
                210, 25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199,
            ]
        );
        let mut bytes = [0u8; 48];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                218, 65, 89, 124, 81, 87, 72, 141, 119, 36, 224, 63, 184, 216, 74, 55, 106, 67,
                184, 244, 21, 24, 161, 28, 195, 135, 182, 105, 178, 238, 101, 134, 159, 7, 231,
                190, 85, 81, 56, 122, 152, 186, 151, 124, 115, 45, 8, 13,
            ]
        );
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [203, 15, 41, 160, 72, 227, 101, 105, 18, 198, 83, 62, 50, 238, 122, 237]
        );
    }
}
