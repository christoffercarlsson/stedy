use crate::{
    ciphers::{Aes128Ctr, Aes256Ctr},
    csprngs::StreamCipherRng,
    hashes::{Sha256, Sha384},
};

pub type Aes128CtrRng = StreamCipherRng<Aes128Ctr, Sha256>;

pub type Aes256CtrRng = StreamCipherRng<Aes256Ctr, Sha384>;

#[cfg(test)]
mod tests {
    use {super::*, crate::traits::SeekableStreamCipher};

    #[test]
    fn test_aes128ctr_rng() {
        let seed = [7u8; 64];
        let mut rng = Aes128CtrRng::from(&seed);
        let mut output = [0u8; 48];
        rng.fill(&mut output);
        let mut expected = [0u8; 48];
        Aes128Ctr::seed(&Sha256::digest(&seed)).apply_keystream(&mut expected);
        assert_eq!(output, expected);
    }

    #[test]
    fn test_aes256ctr_rng() {
        let seed = [7u8; 96];
        let mut rng = Aes256CtrRng::from(&seed);
        let mut output = [0u8; 48];
        rng.fill(&mut output);
        let mut expected = [0u8; 48];
        Aes256Ctr::seed(&Sha384::digest(&seed)).apply_keystream(&mut expected);
        assert_eq!(output, expected);
    }
}
