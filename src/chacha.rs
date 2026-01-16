use crate::traits::{SeekableStreamCipher, StreamCipher};

#[repr(C)]
pub struct ChaCha20 {
    state: [u32; 16],
    keystream: [u8; 64],
    offset: u8,
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self::init(&Self::read_key(key), &Self::read_nonce(nonce))
    }

    pub fn apply_keystream(&mut self, mut data: &mut [u8]) {
        while !data.is_empty() {
            if self.offset == 64 {
                self.next();
            }
            let offset = self.offset as usize;
            let take = data.len().min(64 - offset);
            let keystream = &self.keystream[offset..offset + take];
            let (head, tail) = data.split_at_mut(take);
            for (b, k) in head.iter_mut().zip(keystream.iter()) {
                *b ^= k;
            }
            self.offset += take as u8;
            data = tail;
        }
    }

    pub fn seek(&mut self, counter: u32) {
        self.state[12] = counter;
        self.offset = 64;
    }
}

impl From<&[u8; 32]> for ChaCha20 {
    fn from(key: &[u8; 32]) -> Self {
        Self::new(key, &[0u8; 12])
    }
}

impl From<&[u8; 48]> for ChaCha20 {
    fn from(seed: &[u8; 48]) -> Self {
        let (key, remaining) = seed.split_at(32);
        let (nonce, counter) = remaining.split_at(12);
        let key = <&[u8; 32]>::try_from(key).expect("ChaCha20 seed should contain key bytes");
        let nonce = <&[u8; 12]>::try_from(nonce).expect("ChaCha20 seed should contain nonce bytes");
        let counter =
            <&[u8; 4]>::try_from(counter).expect("ChaCha20 seed should contain counter bytes");
        let counter = u32::from_le_bytes(*counter);
        let mut cipher = Self::new(key, nonce);
        cipher.seek(counter);
        cipher
    }
}

impl StreamCipher for ChaCha20 {
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;

    type Key = [u8; 32];
    type Nonce = [u8; 12];

    fn new(key: &Self::Key, nonce: &Self::Nonce) -> Self {
        Self::new(key, nonce)
    }

    fn apply_keystream(&mut self, message: &mut [u8]) {
        self.apply_keystream(message);
    }
}

impl SeekableStreamCipher for ChaCha20 {
    const SEED_SIZE: usize = 48;

    type Seed = [u8; Self::SEED_SIZE];

    fn seed(seed: &Self::Seed) -> Self {
        Self::from(seed)
    }

    fn seek(&mut self, counter: u32) {
        self.seek(counter);
    }
}

impl ChaCha20 {
    const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    fn init(key: &[u32; 8], nonce: &[u32; 3]) -> Self {
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&Self::SIGMA);
        state[4..12].copy_from_slice(key);
        state[13..16].copy_from_slice(nonce);
        Self {
            state,
            keystream: [0u8; 64],
            offset: 64,
        }
    }

    fn read_key(key: &[u8; 32]) -> [u32; 8] {
        Self::read::<8>(key)
    }

    fn read_nonce(nonce: &[u8; 12]) -> [u32; 3] {
        Self::read::<3>(nonce)
    }

    fn read<const WORDS: usize>(bytes: &[u8]) -> [u32; WORDS] {
        let mut words = [0u32; WORDS];
        let (chunks, _) = bytes.as_chunks::<4>();
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u32::from_le_bytes(*chunk);
        }
        words
    }

    fn next(&mut self) {
        let mut block = self.state;
        Self::rounds(&mut block);
        for (i, b) in block.iter_mut().enumerate() {
            *b = b.wrapping_add(self.state[i]);
        }
        self.state[12] = self.state[12].wrapping_add(1);
        let (chunks, _) = self.keystream.as_chunks_mut::<4>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&block[i].to_le_bytes());
        }
        self.offset = 0;
    }

    fn rounds(block: &mut [u32; 16]) {
        for _ in (0..20).step_by(2) {
            Self::quarter_round(0, 4, 8, 12, block);
            Self::quarter_round(1, 5, 9, 13, block);
            Self::quarter_round(2, 6, 10, 14, block);
            Self::quarter_round(3, 7, 11, 15, block);
            Self::quarter_round(0, 5, 10, 15, block);
            Self::quarter_round(1, 6, 11, 12, block);
            Self::quarter_round(2, 7, 8, 13, block);
            Self::quarter_round(3, 4, 9, 14, block);
        }
    }

    fn quarter_round(a: usize, b: usize, c: usize, d: usize, block: &mut [u32; 16]) {
        block[a] = block[a].wrapping_add(block[b]);
        block[d] = (block[d] ^ block[a]).rotate_left(16);
        block[c] = block[c].wrapping_add(block[d]);
        block[b] = (block[b] ^ block[c]).rotate_left(12);
        block[a] = block[a].wrapping_add(block[b]);
        block[d] = (block[d] ^ block[a]).rotate_left(8);
        block[c] = block[c].wrapping_add(block[d]);
        block[b] = (block[b] ^ block[c]).rotate_left(7);
    }
}

pub struct XChaCha20 {
    inner: ChaCha20,
}

impl XChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        let k = ChaCha20::read_key(key);
        let (n1, n2) = Self::read_nonce(nonce);
        let subkey = Self::calculate_subkey(&k, &n1);
        Self {
            inner: ChaCha20::init(&subkey, &n2),
        }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        self.inner.apply_keystream(data);
    }

    pub fn seek(&mut self, counter: u32) {
        self.inner.seek(counter);
    }
}

impl From<&[u8; 32]> for XChaCha20 {
    fn from(key: &[u8; 32]) -> Self {
        Self::new(key, &[0u8; 24])
    }
}

impl From<&[u8; 60]> for XChaCha20 {
    fn from(seed: &[u8; 60]) -> Self {
        let (key, remaining) = seed.split_at(32);
        let (nonce, counter) = remaining.split_at(24);
        let key = <&[u8; 32]>::try_from(key).expect("XChaCha20 seed should contain key bytes");
        let nonce =
            <&[u8; 24]>::try_from(nonce).expect("XChaCha20 seed should contain nonce bytes");
        let counter =
            <&[u8; 4]>::try_from(counter).expect("XChaCha20 seed should contain counter bytes");
        let counter = u32::from_le_bytes(*counter);
        let mut cipher = Self::new(key, nonce);
        cipher.seek(counter);
        cipher
    }
}

impl StreamCipher for XChaCha20 {
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 24;

    type Key = [u8; Self::KEY_SIZE];
    type Nonce = [u8; Self::NONCE_SIZE];

    fn new(key: &Self::Key, nonce: &Self::Nonce) -> Self {
        Self::new(key, nonce)
    }

    fn apply_keystream(&mut self, message: &mut [u8]) {
        self.apply_keystream(message);
    }
}

impl SeekableStreamCipher for XChaCha20 {
    const SEED_SIZE: usize = 60;

    type Seed = [u8; Self::SEED_SIZE];

    fn seed(seed: &Self::Seed) -> Self {
        Self::from(seed)
    }

    fn seek(&mut self, counter: u32) {
        self.seek(counter);
    }
}

impl XChaCha20 {
    fn read_nonce(nonce: &[u8; 24]) -> ([u32; 4], [u32; 3]) {
        let n1 = ChaCha20::read::<4>(&nonce[0..16]);
        let n2 = ChaCha20::read::<2>(&nonce[16..24]);
        let n2 = [0, n2[0], n2[1]];
        (n1, n2)
    }

    fn calculate_subkey(key: &[u32; 8], nonce: &[u32; 4]) -> [u32; 8] {
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&ChaCha20::SIGMA);
        state[4..12].copy_from_slice(key);
        state[12..16].copy_from_slice(nonce);
        ChaCha20::rounds(&mut state);
        [
            state[0], state[1], state[2], state[3], state[12], state[13], state[14], state[15],
        ]
    }
}
