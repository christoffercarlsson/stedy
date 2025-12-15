use crate::{
    block::Block,
    traits::{Digest, Init},
};

pub struct Sha256 {
    h: [u32; 8],
    block: Block<64>,
    total_size: usize,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: Block::<64>::new(),
            total_size: 0,
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        if let Some((head, tail)) = self.block.blocks(message) {
            self.process_block(&head);
            for (begin, end) in tail {
                self.process_block(&message[begin..end]);
            }
        }
    }

    pub fn finalize_into(mut self, digest: &mut [u8; 32]) {
        self.pad();
        for (i, word) in digest.chunks_mut(4).enumerate() {
            word.copy_from_slice(&self.h[i].to_be_bytes());
        }
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut digest = [0u8; 32];
        self.finalize_into(&mut digest);
        digest
    }
}

pub fn sha256(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize()
}

impl Init for Sha256 {
    fn new() -> Self {
        Self::new()
    }
}

impl Digest for Sha256 {
    type Output = [u8; 32];

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

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn process_block(&mut self, block: &[u8]) {
        let w = Self::schedule(block);
        self.compress(&w);
        self.total_size += block.len();
    }

    fn compress(&mut self, w: &[u32]) {
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];
        for i in 0..64 {
            let t1 = h
                .wrapping_add(Self::big_sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let t2 = Self::big_sigma0(a).wrapping_add(Self::maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
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
        let total_bits = ((self.total_size + remaining.len()) * 8) as u64;
        padding[(padding_size - 8)..padding_size].copy_from_slice(&total_bits.to_be_bytes());
        self.update(&padding[..padding_size]);
    }

    fn small_sigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    fn small_sigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn big_sigma0(a: u32) -> u32 {
        a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22)
    }

    fn big_sigma1(e: u32) -> u32 {
        e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25)
    }

    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn schedule(block: &[u8]) -> [u32; 64] {
        let mut w = [0u32; 64];
        let (words, _) = block.as_chunks::<4>();
        for (i, word) in words.iter().enumerate().take(16) {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = Self::small_sigma0(w[i - 15]);
            let s1 = Self::small_sigma1(w[i - 2]);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        w
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://www.di-mgt.com.au/sha_testvectors.html

    #[test]
    fn test_sha256_0bits() {
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let digest = hasher.finalize();
        assert_eq!(
            digest,
            [
                227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39,
                174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
            ]
        );
    }

    #[test]
    fn test_sha256_24bits() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        let digest = hasher.finalize();
        assert_eq!(
            digest,
            [
                186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35, 176, 3, 97,
                163, 150, 23, 122, 156, 180, 16, 255, 97, 242, 0, 21, 173,
            ]
        );
    }

    #[test]
    fn test_sha256_448bits() {
        let mut hasher = Sha256::new();
        hasher.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let digest = hasher.finalize();
        assert_eq!(
            digest,
            [
                36, 141, 106, 97, 210, 6, 56, 184, 229, 192, 38, 147, 12, 62, 96, 57, 163, 60, 228,
                89, 100, 255, 33, 103, 246, 236, 237, 212, 25, 219, 6, 193,
            ]
        );
    }

    #[test]
    fn test_sha256_896bits() {
        let mut hasher = Sha256::new();
        hasher.update(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let digest = hasher.finalize();
        assert_eq!(
            digest,
            [
                207, 91, 22, 167, 120, 175, 131, 128, 3, 108, 229, 158, 123, 4, 146, 55, 11, 36,
                155, 17, 232, 240, 122, 81, 175, 172, 69, 3, 122, 254, 233, 209,
            ]
        );
    }

    #[test]
    fn test_sha256_1m() {
        let mut hasher = Sha256::new();
        for _ in 0..1000000 {
            hasher.update(b"a");
        }
        let digest = hasher.finalize();
        assert_eq!(
            digest,
            [
                205, 199, 110, 92, 153, 20, 251, 146, 129, 161, 199, 226, 132, 215, 62, 103, 241,
                128, 154, 72, 164, 151, 32, 14, 4, 109, 57, 204, 199, 17, 44, 208,
            ]
        );
    }
}
