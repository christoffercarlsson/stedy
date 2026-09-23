use crate::{
    ciphers::{
        aes::{is_supported, multiply},
        AesCtr,
    },
    traits::{Authenticator, SeekableStreamCipher},
    utils::verify,
};

pub struct GHash {
    h: u128,
    y: u128,
    mask: [u8; 16],
}

impl<const KEY_SIZE: usize> Authenticator<AesCtr<KEY_SIZE>> for GHash
where
    AesCtr<KEY_SIZE>: SeekableStreamCipher,
{
    type Output = [u8; 16];

    fn new(cipher: &mut AesCtr<KEY_SIZE>) -> Self {
        assert!(
            is_supported(),
            "CPU supports AES and carry-less multiply instructions"
        );
        let mut mac = Self {
            h: Self::element(&cipher.hash_subkey()),
            y: 0,
            mask: [0u8; 16],
        };
        cipher.apply_keystream(&mut mac.mask);
        cipher.seek(2);
        mac
    }

    fn tag(mut self, ciphertext: &[u8], aad: Option<&[u8]>) -> Self::Output {
        self.calculate_tag(ciphertext, aad);
        self.finalize()
    }

    fn verify(mut self, ciphertext: &[u8], aad: Option<&[u8]>, tag: &Self::Output) -> bool {
        self.calculate_tag(ciphertext, aad);
        verify(&self.finalize(), tag)
    }
}

impl GHash {
    fn calculate_tag(&mut self, ciphertext: &[u8], aad: Option<&[u8]>) {
        let aad = aad.unwrap_or_default();
        self.update(aad);
        self.update(ciphertext);
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&((aad.len() as u64) << 3).to_be_bytes());
        lengths[8..].copy_from_slice(&((ciphertext.len() as u64) << 3).to_be_bytes());
        self.update(&lengths);
    }

    fn update(&mut self, message: &[u8]) {
        let (batches, remaining) = message.as_chunks::<128>();
        if !batches.is_empty() {
            let powers = self.powers();
            for batch in batches {
                let (blocks, _) = batch.as_chunks::<16>();
                let mut x = [0u128; 8];
                for (x, block) in x.iter_mut().rev().zip(blocks.iter()) {
                    *x = Self::element(block);
                }
                x[7] ^= self.y;
                self.y = multiply(&x, &powers);
            }
        }
        for chunk in remaining.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            self.y = multiply(&[self.y ^ Self::element(&block)], &[self.h]);
        }
    }

    fn powers(&self) -> [u128; 8] {
        let mut powers = [self.h; 8];
        for i in 1..8 {
            powers[i] = multiply(&[powers[i - 1]], &[self.h]);
        }
        powers
    }

    fn finalize(self) -> [u8; 16] {
        let mut tag = self.y.reverse_bits().to_be_bytes();
        for (t, m) in tag.iter_mut().zip(self.mask.iter()) {
            *t ^= m;
        }
        tag
    }

    fn element(block: &[u8; 16]) -> u128 {
        u128::from_be_bytes(*block).reverse_bits()
    }
}
