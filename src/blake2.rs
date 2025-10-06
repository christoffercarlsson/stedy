use crate::{
    block::Block,
    traits::{Digest, Hasher, Init, KeyInit, Mac},
    verify::verify,
};

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

macro_rules! blake2_impl {
    (
        $name:ident,
        $word:ty,
        $block_size:expr,
        $output_size:expr,
        $iv:expr,
        $r1:expr,
        $r2:expr,
        $r3:expr,
        $r4:expr,
        $rounds:expr
    ) => {
        pub struct $name {
            h: [$word; 8],
            t: u128,
            block: Block<{ $block_size }>,
        }

        impl $name {
            const IV: [$word; 8] = $iv;
            const R1: u32 = $r1;
            const R2: u32 = $r2;
            const R3: u32 = $r3;
            const R4: u32 = $r4;
            const BYTES_PER_WORD: usize = (<$word>::BITS / 8) as usize;

            pub fn new(key: Option<&[u8]>) -> Self {
                let mut state = Self {
                    h: Self::IV,
                    t: 0,
                    block: Block::<$block_size>::new(),
                };
                state.init(key);
                state
            }

            fn init(&mut self, key: Option<&[u8]>) {
                let key = key.unwrap_or(&[]);
                let kk = key.len().min($output_size) as $word;
                self.h[0] ^= 0x01010000 ^ (kk << 8) ^ $output_size;
                if !key.is_empty() {
                    let mut block = [0u8; { $block_size }];
                    block[..key.len()].copy_from_slice(key);
                    self.update(&block);
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
                self.t += block.len() as u128;
                self.compress(block, false);
            }

            fn compress(&mut self, block: &[u8], is_final: bool) {
                let mut m = [0 as $word; 16];
                for i in 0..16 {
                    let begin = i * Self::BYTES_PER_WORD;
                    let end = begin + Self::BYTES_PER_WORD;
                    m[i] = <$word>::from_le_bytes(block[begin..end].try_into().unwrap());
                }
                let mut v = [0 as $word; 16];
                v[0..8].copy_from_slice(&self.h);
                v[8..16].copy_from_slice(&Self::IV);
                v[12] ^= self.t as $word;
                v[13] ^= (self.t >> <$word>::BITS) as $word;
                if is_final {
                    v[14] = !v[14];
                }
                for i in 0..$rounds {
                    let s = &SIGMA[i % 10];
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

            fn g(v: &mut [$word; 16], a: usize, b: usize, c: usize, d: usize, x: $word, y: $word) {
                v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
                v[d] = (v[d] ^ v[a]).rotate_right(Self::R1);
                v[c] = v[c].wrapping_add(v[d]);
                v[b] = (v[b] ^ v[c]).rotate_right(Self::R2);
                v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
                v[d] = (v[d] ^ v[a]).rotate_right(Self::R3);
                v[c] = v[c].wrapping_add(v[d]);
                v[b] = (v[b] ^ v[c]).rotate_right(Self::R4);
            }

            pub fn finalize_into(mut self, digest: &mut [u8; $output_size]) {
                let remaining = self.block.remaining();
                let mut block = [0u8; $block_size];
                block[..remaining.len()].copy_from_slice(remaining);
                self.t += remaining.len() as u128;
                self.compress(&block, true);
                for i in 0..8 {
                    let begin = i * Self::BYTES_PER_WORD;
                    let end = begin + Self::BYTES_PER_WORD;
                    digest[begin..end].copy_from_slice(&self.h[i].to_le_bytes());
                }
            }

            pub fn finalize(self) -> [u8; $output_size] {
                let mut digest = [0u8; $output_size];
                self.finalize_into(&mut digest);
                digest
            }

            pub fn verify(self, code: &[u8; $output_size]) -> bool {
                verify(code, &self.finalize())
            }
        }

        impl Init for $name {
            fn new() -> Self {
                Self::new(None)
            }
        }

        impl KeyInit for $name {
            fn new(key: &[u8]) -> Self {
                Self::new(Some(key))
            }
        }

        impl Digest<$output_size> for $name {
            fn update(&mut self, message: &[u8]) {
                self.update(message);
            }

            fn finalize(self) -> [u8; $output_size] {
                self.finalize()
            }

            fn finalize_into(self, digest: &mut [u8; $output_size]) {
                self.finalize_into(digest);
            }
        }

        impl Hasher<$block_size, $output_size> for $name {}

        impl Mac<$output_size> for $name {
            fn verify(self, code: &[u8; $output_size]) -> bool {
                self.verify(code)
            }
        }
    };
}

blake2_impl!(
    Blake2b,
    u64,
    128,
    64,
    [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ],
    32,
    24,
    16,
    63,
    12
);

blake2_impl!(
    Blake2s,
    u32,
    64,
    32,
    [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ],
    16,
    12,
    8,
    7,
    10
);

pub fn blake2b(message: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b::new(None);
    hasher.update(message);
    hasher.finalize()
}

pub fn blake2b_mac(key: &[u8], message: &[u8]) -> [u8; 64] {
    let mut mac = Blake2b::new(Some(key));
    mac.update(message);
    mac.finalize()
}

pub fn blake2b_verify(key: &[u8], message: &[u8], code: &[u8; 64]) -> bool {
    let mut mac = Blake2b::new(Some(key));
    mac.update(message);
    mac.verify(code)
}

pub fn blake2s(message: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s::new(None);
    hasher.update(message);
    hasher.finalize()
}

pub fn blake2s_mac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = Blake2s::new(Some(key));
    mac.update(message);
    mac.finalize()
}

pub fn blake2s_verify(key: &[u8], message: &[u8], code: &[u8; 32]) -> bool {
    let mut mac = Blake2s::new(Some(key));
    mac.update(message);
    mac.verify(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://datatracker.ietf.org/doc/html/rfc7693

    #[test]
    fn test_blake2b() {
        let digest = blake2b(b"abc");
        assert_eq!(
            digest,
            [
                186, 128, 165, 63, 152, 28, 77, 13, 106, 39, 151, 182, 159, 18, 246, 233, 76, 33,
                47, 20, 104, 90, 196, 183, 75, 18, 187, 111, 219, 255, 162, 209, 125, 135, 197, 57,
                42, 171, 121, 45, 194, 82, 213, 222, 69, 51, 204, 149, 24, 211, 138, 168, 219, 241,
                146, 90, 185, 35, 134, 237, 212, 0, 153, 35
            ]
        );
    }

    #[test]
    fn test_blake2s() {
        let digest = blake2s(b"abc");
        assert_eq!(
            digest,
            [
                80, 140, 94, 140, 50, 124, 20, 226, 225, 167, 43, 163, 78, 235, 69, 47, 55, 69,
                139, 32, 158, 214, 58, 41, 77, 153, 155, 76, 134, 103, 89, 130
            ]
        );
    }
}
