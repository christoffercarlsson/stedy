use crate::{ciphers::ChaCha20, csprngs::StreamCipherRng, hashes::Blake2b384};

pub type ChaCha20Rng = StreamCipherRng<ChaCha20, Blake2b384>;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "getrandom")]
    #[test]
    fn test_seed() {
        let mut rng = ChaCha20Rng::seed();
        let mut a = [0u8; 32];
        rng.fill(&mut a);
        assert_ne!(
            a,
            [
                189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102,
                238, 246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 204
            ]
        );
        rng.reseed();
        let mut b = [0u8; 32];
        rng.fill(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn test_fill() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
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
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
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
