use crate::{
    traits::{Digest, Hasher, Init},
    utils::Block,
};

#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    block: Block<64>,
    total_size: u64,
}

impl Sha1 {
    pub fn digest(message: &[u8]) -> [u8; 20] {
        let mut hasher = Self::new();
        hasher.update(message);
        hasher.finalize()
    }

    pub fn new() -> Self {
        Self {
            h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            block: Block::<64>::new(),
            total_size: 0,
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        if let Some((head, tail)) = self.block.blocks(message) {
            self.process_block(&head);
            for block in tail {
                self.process_block(block);
            }
        }
    }

    pub fn finalize_into(mut self, digest: &mut [u8; 20]) {
        self.pad();
        for (i, word) in digest.chunks_mut(4).enumerate() {
            word.copy_from_slice(&self.h[i].to_be_bytes());
        }
    }

    pub fn finalize(self) -> [u8; 20] {
        let mut digest = [0u8; 20];
        self.finalize_into(&mut digest);
        digest
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Init for Sha1 {
    fn new() -> Self {
        Self::new()
    }
}

impl Digest for Sha1 {
    const OUTPUT_SIZE: usize = 20;

    type Output = [u8; Self::OUTPUT_SIZE];

    fn update(&mut self, message: &[u8]) {
        self.update(message);
    }

    fn finalize(self) -> Self::Output {
        self.finalize()
    }

    fn finalize_into(self, output: &mut Self::Output) {
        self.finalize_into(output);
    }
}

impl Hasher for Sha1 {
    const BLOCK_SIZE: usize = 64;

    type Block = [u8; Self::BLOCK_SIZE];

    fn digest(message: &[u8]) -> Self::Output {
        Self::digest(message)
    }
}

impl Sha1 {
    fn process_block(&mut self, block: &[u8]) {
        let words = Self::schedule(block);
        self.compress(&words);
        self.total_size += block.len() as u64;
    }

    fn compress(&mut self, words: &[u32]) {
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        for (i, &w) in words.iter().enumerate().take(80) {
            let t = a
                .rotate_left(5)
                .wrapping_add(Self::f(i, b, c, d))
                .wrapping_add(e)
                .wrapping_add(Self::k(i))
                .wrapping_add(w);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }

    fn pad(&mut self) {
        let mut padding = [0u8; 128];
        padding[0] = 128;
        let remaining = self.block.remaining();
        let padding_size = if remaining.len() < 56 {
            64 - remaining.len()
        } else {
            128 - remaining.len()
        };
        let total_bits = (self.total_size + remaining.len() as u64) * 8;
        padding[(padding_size - 8)..padding_size].copy_from_slice(&total_bits.to_be_bytes());
        self.update(&padding[..padding_size]);
    }

    fn f(t: usize, b: u32, c: u32, d: u32) -> u32 {
        match t {
            0..=19 => (b & c) | ((!b) & d),
            40..=59 => (b & c) | (b & d) | (c & d),
            _ => b ^ c ^ d,
        }
    }

    fn k(t: usize) -> u32 {
        match t {
            0..=19 => 0x5a827999,
            20..=39 => 0x6ed9eba1,
            40..=59 => 0x8f1bbcdc,
            _ => 0xca62c1d6,
        }
    }

    fn schedule(block: &[u8]) -> [u32; 80] {
        let mut w = [0u32; 80];
        let (words, _) = block.as_chunks::<4>();
        for (i, &word) in words.iter().enumerate().take(16) {
            w[i] = u32::from_be_bytes(word);
        }
        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }
        w
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://www.di-mgt.com.au/sha_testvectors.html

    #[test]
    fn test_sha1_0bits() {
        let digest = Sha1::digest(b"");
        assert_eq!(
            digest,
            [
                218, 57, 163, 238, 94, 107, 75, 13, 50, 85, 191, 239, 149, 96, 24, 144, 175, 216,
                7, 9
            ]
        );
    }

    #[test]
    fn test_sha1_24bits() {
        let digest = Sha1::digest(b"abc");
        assert_eq!(
            digest,
            [
                169, 153, 62, 54, 71, 6, 129, 106, 186, 62, 37, 113, 120, 80, 194, 108, 156, 208,
                216, 157
            ]
        );
    }

    #[test]
    fn test_sha1_448bits() {
        let digest = Sha1::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            digest,
            [
                132, 152, 62, 68, 28, 59, 210, 110, 186, 174, 74, 161, 249, 81, 41, 229, 229, 70,
                112, 241
            ]
        );
    }

    #[test]
    fn test_sha1_896bits() {
        let digest = Sha1::digest(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        assert_eq!(
            digest,
            [
                164, 155, 36, 70, 160, 44, 100, 91, 244, 25, 249, 149, 182, 112, 145, 37, 58, 4,
                162, 89
            ]
        );
    }

    #[test]
    fn test_sha1_1m() {
        let mut hasher = Sha1::new();
        for _ in 0..1000000 {
            hasher.update(b"a");
        }
        let digest = hasher.finalize();
        assert_eq!(
            digest,
            [
                52, 170, 151, 60, 212, 196, 218, 164, 246, 30, 235, 43, 219, 173, 39, 49, 101, 52,
                1, 111
            ]
        );
    }
}
