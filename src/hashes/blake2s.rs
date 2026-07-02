use crate::{
    traits::{Digest, Hasher, Init, KeyInit, Mac, Prf},
    utils::{verify, Block},
};

#[derive(Clone)]
pub struct Blake2s<const N: usize> {
    h: [u32; 8],
    t: u64,
    block: Block<64>,
}

impl<const N: usize> Blake2s<N> {
    pub fn digest(message: &[u8]) -> [u8; N] {
        let mut hasher = Self::new(None);
        hasher.update(message);
        hasher.finalize()
    }

    pub fn new(key: Option<&[u8]>) -> Self {
        let mut state = Self {
            h: Self::IV,
            t: 0,
            block: Block::<64>::new(),
        };
        state.init(key);
        state
    }

    pub fn update(&mut self, message: &[u8]) {
        if let Some((head, tail)) = self.block.blocks(message) {
            self.process_block(&head);
            for block in tail {
                self.process_block(block);
            }
        }
    }

    pub fn finalize_into(mut self, digest: &mut [u8; N]) {
        let remaining = self.block.remaining();
        let mut block = [0u8; 64];
        block[..remaining.len()].copy_from_slice(remaining);
        self.t += remaining.len() as u64;
        self.compress(&block, 1);
        for (i, dest) in digest.chunks_mut(4).take(8).enumerate() {
            let src = self.h[i].to_le_bytes();
            dest.copy_from_slice(&src[..dest.len()]);
        }
    }

    pub fn finalize(self) -> [u8; N] {
        let mut digest = [0u8; N];
        self.finalize_into(&mut digest);
        digest
    }

    pub fn verify(self, code: &[u8; N]) -> bool {
        verify(code, &self.finalize())
    }
}

impl<const N: usize> Init for Blake2s<N> {
    fn new() -> Self {
        Self::new(None)
    }
}

impl<const N: usize> KeyInit for Blake2s<N> {
    fn new(key: &[u8]) -> Self {
        Self::new(Some(key))
    }
}

impl<const N: usize> Digest for Blake2s<N> {
    const OUTPUT_SIZE: usize = N;

    type Output = [u8; N];

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

impl<const N: usize> Mac for Blake2s<N> {
    fn verify(self, code: &[u8; N]) -> bool {
        self.verify(code)
    }
}

pub type Blake2s256 = Blake2s<32>;
pub type Blake2s224 = Blake2s<28>;
pub type Blake2s160 = Blake2s<20>;
pub type Blake2s128 = Blake2s<16>;

macro_rules! impl_hasher_prf {
    ($($t:ty),*) => {
        $(
            impl Hasher for $t {
                const BLOCK_SIZE: usize = 64;

                type Block = [u8; 64];

                fn digest(message: &[u8]) -> Self::Output {
                    Self::digest(message)
                }
            }

            impl Prf for $t {}
        )*
    };
}

impl_hasher_prf!(Blake2s256, Blake2s224, Blake2s160, Blake2s128);

impl<const N: usize> Blake2s<N> {
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const SIGMA: [[usize; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];

    fn init(&mut self, key: Option<&[u8]>) {
        let key = key.unwrap_or_default();
        let kk = key.len().min(32);
        let nn = N.min(32);
        self.h[0] ^= 0x01010000 ^ ((kk as u32) << 8) ^ (nn as u32);
        if !key.is_empty() {
            let mut block = [0u8; 64];
            block[..kk].copy_from_slice(&key[..kk]);
            self.update(&block);
        }
    }

    fn process_block(&mut self, block: &[u8]) {
        self.t += block.len() as u64;
        self.compress(block, 0);
    }

    fn compress(&mut self, block: &[u8], is_final: u32) {
        let mut m = [0u32; 16];
        let (chunks, _) = block.as_chunks::<4>();
        for (i, chunk) in chunks.iter().take(16).enumerate() {
            m[i] = u32::from_le_bytes(*chunk);
        }
        let mut v = [0u32; 16];
        v[0..8].copy_from_slice(&self.h);
        v[8..16].copy_from_slice(&Self::IV);
        v[12] ^= self.t as u32;
        v[13] ^= (self.t >> 32) as u32;
        v[14] ^= is_final.wrapping_neg();
        for i in 0..10 {
            let s = &Self::SIGMA[i % 10];
            Self::g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            Self::g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            Self::g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            Self::g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            Self::g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            Self::g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            Self::g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            Self::g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(12);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(8);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(7);
    }
}

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    // https://datatracker.ietf.org/doc/html/rfc7693#appendix-B

    #[test]
    fn test_blake2s() {
        let digest = Blake2s256::digest(b"abc");
        assert_eq!(
            digest,
            hex!(
                "50 8C 5E 8C 32 7C 14 E2 E1 A7 2B A3 4E EB 45 2F
                37 45 8B 20 9E D6 3A 29 4D 99 9B 4C 86 67 59 82"
            )
        );
    }
}
