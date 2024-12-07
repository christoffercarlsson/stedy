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
    for (i, word) in block.chunks(8).enumerate().take(16) {
        w[i] = u64::from_be_bytes(word.try_into().unwrap());
    }
    for i in 16..80 {
        let s0 = small_sigma0(w[i - 15]);
        let s1 = small_sigma1(w[i - 2]);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    w
}

pub struct Sha512 {
    h0: u64,
    h1: u64,
    h2: u64,
    h3: u64,
    h4: u64,
    h5: u64,
    h6: u64,
    h7: u64,
    buffer: [u8; 128],
    buffer_size: usize,
    total_size: usize,
}

impl Sha512 {
    pub fn new() -> Self {
        Self {
            h0: 0x6a09e667f3bcc908,
            h1: 0xbb67ae8584caa73b,
            h2: 0x3c6ef372fe94f82b,
            h3: 0xa54ff53a5f1d36f1,
            h4: 0x510e527fade682d1,
            h5: 0x9b05688c2b3e6c1f,
            h6: 0x1f83d9abfb41bd6b,
            h7: 0x5be0cd19137e2179,
            buffer: [0u8; 128],
            buffer_size: 0,
            total_size: 0,
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        let offset = self.process_buffer(message);
        for chunk in message[offset..].chunks(128) {
            if chunk.len() == 128 {
                self.process_block(chunk);
            } else {
                self.buffer_chunk(chunk);
            }
        }
    }

    fn process_buffer(&mut self, message: &[u8]) -> usize {
        let offset = message.len().min(128 - self.buffer_size);
        self.buffer_chunk(&message[..offset]);
        if self.buffer_size == 128 {
            self.process_block(&self.buffer.clone());
            self.buffer_size = 0;
        }
        offset
    }

    fn buffer_chunk(&mut self, chunk: &[u8]) {
        self.buffer[self.buffer_size..self.buffer_size + chunk.len()].copy_from_slice(chunk);
        self.buffer_size += chunk.len();
    }

    fn process_block(&mut self, block: &[u8]) {
        let w = schedule(block);
        self.compress(&w);
        self.total_size += block.len();
    }

    fn compress(&mut self, w: &[u64]) {
        let mut a = self.h0;
        let mut b = self.h1;
        let mut c = self.h2;
        let mut d = self.h3;
        let mut e = self.h4;
        let mut f = self.h5;
        let mut g = self.h6;
        let mut h = self.h7;
        for i in 0..80 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.h0 = self.h0.wrapping_add(a);
        self.h1 = self.h1.wrapping_add(b);
        self.h2 = self.h2.wrapping_add(c);
        self.h3 = self.h3.wrapping_add(d);
        self.h4 = self.h4.wrapping_add(e);
        self.h5 = self.h5.wrapping_add(f);
        self.h6 = self.h6.wrapping_add(g);
        self.h7 = self.h7.wrapping_add(h);
    }

    pub fn finalize_into(mut self, digest: &mut [u8; 64]) {
        self.pad();
        digest[0..8].copy_from_slice(&self.h0.to_be_bytes());
        digest[8..16].copy_from_slice(&self.h1.to_be_bytes());
        digest[16..24].copy_from_slice(&self.h2.to_be_bytes());
        digest[24..32].copy_from_slice(&self.h3.to_be_bytes());
        digest[32..40].copy_from_slice(&self.h4.to_be_bytes());
        digest[40..48].copy_from_slice(&self.h5.to_be_bytes());
        digest[48..56].copy_from_slice(&self.h6.to_be_bytes());
        digest[56..64].copy_from_slice(&self.h7.to_be_bytes());
    }

    pub fn finalize(self) -> [u8; 64] {
        let mut digest = [0u8; 64];
        self.finalize_into(&mut digest);
        digest
    }

    fn pad(&mut self) {
        let mut padding = [0u8; 256];
        padding[0] = 128;
        let padding_size = if self.buffer_size < 112 {
            128 - self.buffer_size
        } else {
            256 - self.buffer_size
        };
        let total_bits = (self.total_size as u128 + self.buffer_size as u128) * 8;
        padding[(padding_size - 16)..padding_size].copy_from_slice(&total_bits.to_be_bytes());
        self.update(&padding[..padding_size]);
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Sha512::new()
    }
}

pub fn sha512(message: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(message);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://www.di-mgt.com.au/sha_testvectors.html

    #[test]
    fn test_sha512_0bits() {
        let mut hasher = Sha512::new();
        hasher.update(b"");
        let digest = hasher.finalize();

        let expected = [
            207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214, 32, 228,
            5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208, 209, 60, 93, 133,
            242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49, 189, 71, 65, 122, 129,
            165, 56, 50, 122, 249, 39, 218, 62,
        ];

        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha512_24bits() {
        let mut hasher = Sha512::new();
        hasher.update(b"abc");
        let digest = hasher.finalize();

        let expected = [
            221, 175, 53, 161, 147, 97, 122, 186, 204, 65, 115, 73, 174, 32, 65, 49, 18, 230, 250,
            78, 137, 169, 126, 162, 10, 158, 238, 230, 75, 85, 211, 154, 33, 146, 153, 42, 39, 79,
            193, 168, 54, 186, 60, 35, 163, 254, 235, 189, 69, 77, 68, 35, 100, 60, 232, 14, 42,
            154, 201, 79, 165, 76, 164, 159,
        ];

        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha512_448bits() {
        let mut hasher = Sha512::new();
        hasher.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let digest = hasher.finalize();

        let expected = [
            32, 74, 143, 198, 221, 168, 47, 10, 12, 237, 123, 235, 142, 8, 164, 22, 87, 193, 110,
            244, 104, 178, 40, 168, 39, 155, 227, 49, 167, 3, 195, 53, 150, 253, 21, 193, 59, 27,
            7, 249, 170, 29, 59, 234, 87, 120, 156, 160, 49, 173, 133, 199, 167, 29, 215, 3, 84,
            236, 99, 18, 56, 202, 52, 69,
        ];

        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha512_896bits() {
        let mut hasher = Sha512::new();
        hasher.update(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let digest = hasher.finalize();

        let expected = [
            142, 149, 155, 117, 218, 227, 19, 218, 140, 244, 247, 40, 20, 252, 20, 63, 143, 119,
            121, 198, 235, 159, 127, 161, 114, 153, 174, 173, 182, 136, 144, 24, 80, 29, 40, 158,
            73, 0, 247, 228, 51, 27, 153, 222, 196, 181, 67, 58, 199, 211, 41, 238, 182, 221, 38,
            84, 94, 150, 229, 91, 135, 75, 233, 9,
        ];

        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha512_1m() {
        let mut hasher = Sha512::new();
        for _ in 0..1000000 {
            hasher.update(b"a");
        }
        let digest = hasher.finalize();

        let expected = [
            231, 24, 72, 61, 12, 231, 105, 100, 78, 46, 66, 199, 188, 21, 180, 99, 142, 31, 152,
            177, 59, 32, 68, 40, 86, 50, 168, 3, 175, 169, 115, 235, 222, 15, 242, 68, 135, 126,
            166, 10, 76, 176, 67, 44, 229, 119, 195, 27, 235, 0, 156, 92, 44, 73, 170, 46, 78, 173,
            178, 23, 173, 140, 192, 155,
        ];

        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha512_1gb() {
        let mut hasher = Sha512::new();
        for _ in 0..16777216 {
            hasher.update(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");
        }
        let digest = hasher.finalize();

        let expected = [
            180, 124, 147, 52, 33, 234, 45, 177, 73, 173, 110, 16, 252, 230, 199, 249, 61, 7, 82,
            56, 1, 128, 255, 215, 244, 98, 154, 113, 33, 52, 131, 29, 119, 190, 96, 145, 184, 25,
            237, 53, 44, 41, 103, 162, 226, 212, 250, 80, 80, 114, 60, 150, 48, 105, 31, 26, 5,
            167, 40, 29, 190, 108, 16, 134,
        ];

        assert_eq!(digest, expected);
    }
}
