use crate::traits::{SeekableStreamCipher, StreamCipher};

pub struct Salsa20 {
    state: [u32; 16],
    keystream: [u8; 64],
    offset: u8,
}

impl Salsa20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 8]) -> Self {
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
        self.state[8] = counter;
        self.state[9] = 0;
        self.offset = 64;
    }
}

impl From<&[u8; 32]> for Salsa20 {
    fn from(key: &[u8; 32]) -> Self {
        Self::new(key, &[0u8; 8])
    }
}

impl From<&[u8; 44]> for Salsa20 {
    fn from(seed: &[u8; 44]) -> Self {
        let (key, remaining) = seed.split_at(32);
        let (nonce, counter) = remaining.split_at(8);
        let key = <&[u8; 32]>::try_from(key).expect("Salsa20 key fits within the seed");
        let nonce = <&[u8; 8]>::try_from(nonce).expect("Salsa20 nonce fits within the seed");
        let counter = <&[u8; 4]>::try_from(counter).expect("Salsa20 counter fits within the seed");
        let counter = u32::from_le_bytes(*counter);
        let mut cipher = Self::new(key, nonce);
        cipher.seek(counter);
        cipher
    }
}

impl StreamCipher for Salsa20 {
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 8;

    type Key = [u8; Self::KEY_SIZE];
    type Nonce = [u8; Self::NONCE_SIZE];

    fn new(key: &Self::Key, nonce: &Self::Nonce) -> Self {
        Self::new(key, nonce)
    }

    fn apply_keystream(&mut self, message: &mut [u8]) {
        self.apply_keystream(message);
    }
}

impl SeekableStreamCipher for Salsa20 {
    const SEED_SIZE: usize = 44;

    type Seed = [u8; Self::SEED_SIZE];

    fn seed(seed: &Self::Seed) -> Self {
        Self::from(seed)
    }

    fn seek(&mut self, counter: u32) {
        self.seek(counter);
    }
}

impl Salsa20 {
    const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    fn init(key: &[u32; 8], nonce: &[u32; 2]) -> Self {
        Self {
            state: Self::state(key, &[nonce[0], nonce[1], 0, 0]),
            keystream: [0u8; 64],
            offset: 64,
        }
    }

    fn state(key: &[u32; 8], nonce: &[u32; 4]) -> [u32; 16] {
        let mut state = [0u32; 16];
        state[0] = Self::SIGMA[0];
        state[5] = Self::SIGMA[1];
        state[10] = Self::SIGMA[2];
        state[15] = Self::SIGMA[3];
        state[1..5].copy_from_slice(&key[0..4]);
        state[11..15].copy_from_slice(&key[4..8]);
        state[6..10].copy_from_slice(nonce);
        state
    }

    fn read_key(key: &[u8; 32]) -> [u32; 8] {
        Self::read::<8>(key)
    }

    fn read_nonce(nonce: &[u8; 8]) -> [u32; 2] {
        Self::read::<2>(nonce)
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
        let (counter, carry) = self.state[8].overflowing_add(1);
        self.state[8] = counter;
        self.state[9] = self.state[9].wrapping_add(carry as u32);
        let (chunks, _) = self.keystream.as_chunks_mut::<4>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&block[i].to_le_bytes());
        }
        self.offset = 0;
    }

    fn rounds(block: &mut [u32; 16]) {
        for _ in (0..20).step_by(2) {
            Self::quarter_round(0, 4, 8, 12, block);
            Self::quarter_round(5, 9, 13, 1, block);
            Self::quarter_round(10, 14, 2, 6, block);
            Self::quarter_round(15, 3, 7, 11, block);
            Self::quarter_round(0, 1, 2, 3, block);
            Self::quarter_round(5, 6, 7, 4, block);
            Self::quarter_round(10, 11, 8, 9, block);
            Self::quarter_round(15, 12, 13, 14, block);
        }
    }

    fn quarter_round(a: usize, b: usize, c: usize, d: usize, block: &mut [u32; 16]) {
        block[b] ^= block[a].wrapping_add(block[d]).rotate_left(7);
        block[c] ^= block[b].wrapping_add(block[a]).rotate_left(9);
        block[d] ^= block[c].wrapping_add(block[b]).rotate_left(13);
        block[a] ^= block[d].wrapping_add(block[c]).rotate_left(18);
    }
}

pub struct XSalsa20 {
    inner: Salsa20,
}

impl XSalsa20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        let k = Salsa20::read_key(key);
        let (n1, n2) = Self::read_nonce(nonce);
        let subkey = Self::calculate_subkey(&k, &n1);
        Self {
            inner: Salsa20::init(&subkey, &n2),
        }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        self.inner.apply_keystream(data);
    }

    pub fn seek(&mut self, counter: u32) {
        self.inner.seek(counter);
    }
}

impl From<&[u8; 32]> for XSalsa20 {
    fn from(key: &[u8; 32]) -> Self {
        Self::new(key, &[0u8; 24])
    }
}

impl From<&[u8; 60]> for XSalsa20 {
    fn from(seed: &[u8; 60]) -> Self {
        let (key, remaining) = seed.split_at(32);
        let (nonce, counter) = remaining.split_at(24);
        let key = <&[u8; 32]>::try_from(key).expect("XSalsa20 key fits within the seed");
        let nonce = <&[u8; 24]>::try_from(nonce).expect("XSalsa20 nonce fits within the seed");
        let counter = <&[u8; 4]>::try_from(counter).expect("XSalsa20 counter fits within the seed");
        let counter = u32::from_le_bytes(*counter);
        let mut cipher = Self::new(key, nonce);
        cipher.seek(counter);
        cipher
    }
}

impl StreamCipher for XSalsa20 {
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

impl SeekableStreamCipher for XSalsa20 {
    const SEED_SIZE: usize = 60;

    type Seed = [u8; Self::SEED_SIZE];

    fn seed(seed: &Self::Seed) -> Self {
        Self::from(seed)
    }

    fn seek(&mut self, counter: u32) {
        self.seek(counter);
    }
}

impl XSalsa20 {
    fn read_nonce(nonce: &[u8; 24]) -> ([u32; 4], [u32; 2]) {
        let n1 = Salsa20::read::<4>(&nonce[0..16]);
        let n2 = Salsa20::read::<2>(&nonce[16..24]);
        (n1, n2)
    }

    fn calculate_subkey(key: &[u32; 8], nonce: &[u32; 4]) -> [u32; 8] {
        let mut state = Salsa20::state(key, nonce);
        Salsa20::rounds(&mut state);
        [
            state[0], state[5], state[10], state[15], state[6], state[7], state[8], state[9],
        ]
    }
}
