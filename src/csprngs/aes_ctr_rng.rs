use crate::{
    ciphers::{Aes128Ctr, Aes256Ctr},
    csprngs::StreamCipherRng,
    hashes::{Sha256, Sha384},
};

pub type Aes128CtrRng = StreamCipherRng<Aes128Ctr, Sha256>;
pub type Aes256CtrRng = StreamCipherRng<Aes256Ctr, Sha384>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128ctr_rng() {
        let seed = [0u8; 64];
        let mut rng = Aes128CtrRng::from(&seed);
        let mut output = [0u8; 48];
        rng.fill(&mut output).unwrap();
        assert_eq!(
            output,
            [
                172, 97, 163, 86, 247, 21, 103, 60, 183, 104, 17, 115, 138, 212, 25, 237, 181, 137,
                154, 62, 160, 187, 241, 192, 174, 76, 139, 104, 168, 179, 167, 102, 152, 220, 75,
                168, 23, 14, 121, 130, 88, 144, 17, 92, 201, 174, 68, 82
            ]
        );
    }

    #[test]
    fn test_aes256ctr_rng() {
        let seed = [0u8; 96];
        let mut rng = Aes256CtrRng::from(&seed);
        let mut output = [0u8; 48];
        rng.fill(&mut output).unwrap();
        assert_eq!(
            output,
            [
                8, 251, 245, 5, 176, 0, 241, 235, 248, 45, 128, 194, 75, 34, 51, 232, 166, 94, 30,
                186, 164, 209, 255, 226, 22, 251, 88, 159, 88, 80, 192, 201, 138, 207, 208, 6, 21,
                146, 65, 126, 69, 190, 132, 161, 159, 2, 179, 30
            ]
        );
    }
}
