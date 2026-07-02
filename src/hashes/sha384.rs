use crate::{
    traits::{Digest, Hasher, Init},
    utils::Block,
};

#[derive(Clone)]
pub struct Sha384 {
    h: [u64; 8],
    block: Block<128>,
    total_size: u64,
}

impl Sha384 {
    pub fn digest(message: &[u8]) -> [u8; 48] {
        let mut hasher = Self::new();
        hasher.update(message);
        hasher.finalize()
    }

    pub fn new() -> Self {
        Self {
            h: [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4,
            ],
            block: Block::<128>::new(),
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

    pub fn finalize_into(mut self, digest: &mut [u8; 48]) {
        self.pad();
        for (i, word) in digest.chunks_mut(8).enumerate() {
            word.copy_from_slice(&self.h[i].to_be_bytes());
        }
    }

    pub fn finalize(self) -> [u8; 48] {
        let mut digest = [0u8; 48];
        self.finalize_into(&mut digest);
        digest
    }
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Init for Sha384 {
    fn new() -> Self {
        Self::new()
    }
}

impl Digest for Sha384 {
    const OUTPUT_SIZE: usize = 48;

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

impl Hasher for Sha384 {
    const BLOCK_SIZE: usize = 128;

    type Block = [u8; Self::BLOCK_SIZE];

    fn digest(message: &[u8]) -> Self::Output {
        Self::digest(message)
    }
}

impl Sha384 {
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    fn process_block(&mut self, block: &[u8]) {
        let words = Self::schedule(block);
        self.compress(&words);
        self.total_size += block.len() as u64;
    }

    fn compress(&mut self, words: &[u64]) {
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];
        for (i, &w) in words.iter().enumerate().take(80) {
            let t1 = h
                .wrapping_add(Self::big_sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(Self::K[i])
                .wrapping_add(w);
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
        let mut padding = [0u8; 256];
        padding[0] = 128;
        let remaining = self.block.remaining();
        let padding_size = if remaining.len() < 112 {
            128 - remaining.len()
        } else {
            256 - remaining.len()
        };
        let total_bits = ((self.total_size + remaining.len() as u64) * 8) as u128;
        padding[(padding_size - 16)..padding_size].copy_from_slice(&total_bits.to_be_bytes());
        self.update(&padding[..padding_size]);
    }

    fn small_sigma0(x: u64) -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
    }

    fn small_sigma1(x: u64) -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
    }

    fn big_sigma0(a: u64) -> u64 {
        a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39)
    }

    fn big_sigma1(e: u64) -> u64 {
        e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41)
    }

    fn ch(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (!x & z)
    }

    fn maj(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn schedule(block: &[u8]) -> [u64; 80] {
        let mut w = [0u64; 80];
        let (words, _) = block.as_chunks::<8>();
        for (i, &word) in words.iter().enumerate().take(16) {
            w[i] = u64::from_be_bytes(word);
        }
        for i in 16..80 {
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
    use {super::*, hex_literal::hex};

    // https://www.di-mgt.com.au/sha_testvectors.html

    #[test]
    fn test_sha384_0bits() {
        let digest = Sha384::digest(b"");
        assert_eq!(
            digest,
            hex!("38b060a751ac9638 4cd9327eb1b1e36a 21fdb71114be0743 4c0cc7bf63f6e1da 274edebfe76f65fb d51ad2f14898b95b")
        );
    }

    #[test]
    fn test_sha384_24bits() {
        let digest = Sha384::digest(b"abc");
        assert_eq!(
            digest,
            hex!("cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7")
        );
    }

    #[test]
    fn test_sha384_448bits() {
        let digest = Sha384::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            digest,
            hex!("3391fdddfc8dc739 3707a65b1b470939 7cf8b1d162af05ab fe8f450de5f36bc6 b0455a8520bc4e6f 5fe95b1fe3c8452b")
        );
    }

    #[test]
    fn test_sha384_896bits() {
        let digest =
            Sha384::digest(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        assert_eq!(
            digest,
            hex!("09330c33f71147e8 3d192fc782cd1b47 53111b173b3b05d2 2fa08086e3b0f712 fcc7c71a557e2db9 66c3e9fa91746039"),
        );
    }

    #[test]
    fn test_sha384_1m() {
        let mut hasher = Sha384::new();
        for _ in 0..1000000 {
            hasher.update(b"a");
        }
        let digest = hasher.finalize();
        assert_eq!(
            digest,
            hex!("9d0e1809716474cb 086e834e310a4a1c ed149e9c00f24852 7972cec5704c2a5b 07b8b3dc38ecc4eb ae97ddd87f3d8985")
        );
    }
}
