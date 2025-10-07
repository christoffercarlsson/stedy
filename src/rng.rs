use crate::chacha::ChaCha20;

pub struct Rng {
    cipher: ChaCha20,
    buffer: [u8; 64],
    index: usize,
}

#[allow(dead_code)]
impl Rng {
    fn refill_buffer(&mut self) {
        self.cipher.apply_keystream(&mut self.buffer);
        self.index = 0;
    }

    pub fn next_u32(&mut self) -> u32 {
        if self.index + 4 > 64 {
            self.refill_buffer();
        }
        let result =
            u32::from_le_bytes(self.buffer[self.index..self.index + 4].try_into().unwrap());
        self.index += 4;
        result
    }

    pub fn next_u64(&mut self) -> u64 {
        if self.index + 8 > 64 {
            self.refill_buffer();
        }
        let result =
            u64::from_le_bytes(self.buffer[self.index..self.index + 8].try_into().unwrap());
        self.index += 8;
        result
    }

    pub fn fill(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(64) {
            if self.index == 64 {
                self.refill_buffer();
            }
            let remaining = 64 - self.index;
            let size = chunk.len().min(remaining);
            chunk.copy_from_slice(&self.buffer[self.index..self.index + size]);
            self.index += size;
        }
    }
}

impl From<&[u8; 32]> for Rng {
    fn from(value: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20::from(value, &[0u8; 12]),
            buffer: [0u8; 64],
            index: 64,
        }
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
        let mut bytes = [0u8; 96];
        rng.fill(&mut bytes);
        assert_eq!(
            bytes,
            [
                118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189,
                210, 25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199, 218, 65, 89,
                124, 81, 87, 72, 141, 119, 36, 224, 63, 184, 216, 74, 55, 106, 67, 184, 244, 21,
                24, 161, 28, 195, 135, 182, 105, 178, 238, 101, 134, 233, 191, 7, 19, 245, 160, 5,
                234, 216, 231, 253, 153, 32, 171, 181, 37, 118, 221, 48, 24, 232, 110, 136, 115,
                186, 240, 188, 242, 185, 153, 119, 42
            ]
        );
    }
}
