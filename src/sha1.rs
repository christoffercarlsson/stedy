use crate::{
    block::Block,
    traits::{Digest, Hasher, Init},
};

type Sha1Block = Block<64>;

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
    for (i, word) in block.chunks(4).enumerate().take(16) {
        w[i] = u32::from_be_bytes(word.try_into().unwrap());
    }
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }
    w
}

#[derive(Copy, Clone)]
pub struct Sha1 {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    block: Sha1Block,
    total_size: usize,
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            h0: 0x67452301,
            h1: 0xefcdaB89,
            h2: 0x98badcfe,
            h3: 0x10325476,
            h4: 0xc3d2E1f0,
            block: Sha1Block::new(),
            total_size: 0,
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        let (head, tail) = self.block.blocks(message);
        if let Some(head) = head {
            self.process_block(&head);
        }
        for (begin, end) in tail {
            self.process_block(&message[begin..end]);
        }
    }

    fn process_block(&mut self, block: &[u8]) {
        let w = schedule(block);
        self.compress(&w);
        self.total_size += block.len();
    }

    fn compress(&mut self, w: &[u32]) {
        let mut a = self.h0;
        let mut b = self.h1;
        let mut c = self.h2;
        let mut d = self.h3;
        let mut e = self.h4;
        for i in 0..80 {
            let t = a
                .rotate_left(5)
                .wrapping_add(f(i, b, c, d))
                .wrapping_add(e)
                .wrapping_add(k(i))
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        self.h0 = self.h0.wrapping_add(a);
        self.h1 = self.h1.wrapping_add(b);
        self.h2 = self.h2.wrapping_add(c);
        self.h3 = self.h3.wrapping_add(d);
        self.h4 = self.h4.wrapping_add(e);
    }

    pub fn finalize_into(mut self, digest: &mut [u8; 20]) {
        self.pad();
        digest[0..4].copy_from_slice(&self.h0.to_be_bytes());
        digest[4..8].copy_from_slice(&self.h1.to_be_bytes());
        digest[8..12].copy_from_slice(&self.h2.to_be_bytes());
        digest[12..16].copy_from_slice(&self.h3.to_be_bytes());
        digest[16..20].copy_from_slice(&self.h4.to_be_bytes());
    }

    pub fn finalize(self) -> [u8; 20] {
        let mut digest = [0u8; 20];
        self.finalize_into(&mut digest);
        digest
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
        let total_bits = (self.total_size + remaining.len()) * 8;
        padding[(padding_size - 8)..padding_size].copy_from_slice(&total_bits.to_be_bytes());
        self.update(&padding[..padding_size]);
    }
}

impl Init for Sha1 {
    fn new() -> Self {
        Self::new()
    }
}

impl Digest<20> for Sha1 {
    fn update(&mut self, message: &[u8]) {
        self.update(message);
    }

    fn finalize(self) -> [u8; 20] {
        self.finalize()
    }

    fn finalize_into(self, output: &mut [u8; 20]) {
        self.finalize_into(output);
    }
}

impl Hasher<64, 20> for Sha1 {}

#[cfg(test)]
mod tests {
    use super::*;

    // https://www.di-mgt.com.au/sha_testvectors.html

    #[test]
    fn test_sha1_0bits() {
        let mut hasher = Sha1::new();
        hasher.update(b"");
        let digest = hasher.finalize();
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
        let mut hasher = Sha1::new();
        hasher.update(b"abc");
        let digest = hasher.finalize();
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
        let mut hasher = Sha1::new();
        hasher.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let digest = hasher.finalize();
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
        let mut hasher = Sha1::new();
        hasher.update(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let digest = hasher.finalize();
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
