use crate::{
    Error,
    traits::{SeekableStreamCipher, StreamCipher},
    utils::{Secret, Word},
};

pub struct ChaCha20 {
    state: Secret<[u32; 16]>,
    keystream: Secret<[u8; 64]>,
    offset: u8,
    blocks: u64,
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut words = Secret::from([0u32; 8]);
        Self::read(key, words.get_mut());
        Self::init(words.get(), &Self::read_nonce(nonce))
    }

    pub fn apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), Error> {
        if data.len() as u64 > self.available() {
            return Err(Error::LimitExceeded);
        }
        while !data.is_empty() {
            if self.offset == 64 && data.len() >= 256 {
                let (head, tail) = data.split_at_mut(256);
                self.next_blocks(head);
                data = tail;
                continue;
            }
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
        Ok(())
    }

    pub fn seek(&mut self, counter: u32) {
        self.state[12] = counter;
        self.offset = 64;
        self.blocks = u64::from(u32::MAX - counter) + 1;
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
        let key = <&[u8; 32]>::try_from(key).expect("ChaCha20 key fits within the seed");
        let nonce = <&[u8; 12]>::try_from(nonce).expect("ChaCha20 nonce fits within the seed");
        let counter = <&[u8; 4]>::try_from(counter).expect("ChaCha20 counter fits within the seed");
        let counter = u32::from_le_bytes(*counter);
        let mut cipher = Self::new(key, nonce);
        cipher.seek(counter);
        cipher.blocks = u64::MAX;
        cipher
    }
}

pub struct XChaCha20 {
    inner: ChaCha20,
}

impl XChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        let mut words = Secret::from([0u32; 8]);
        ChaCha20::read(key, words.get_mut());
        let (n1, n2) = Self::read_nonce(nonce);
        let mut subkey = Secret::from([0u32; 8]);
        Self::calculate_subkey(words.get(), &n1, subkey.get_mut());
        Self {
            inner: ChaCha20::init(subkey.get(), &n2),
        }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.inner.apply_keystream(data)
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
        let key = <&[u8; 32]>::try_from(key).expect("XChaCha20 key fits within the seed");
        let nonce = <&[u8; 24]>::try_from(nonce).expect("XChaCha20 nonce fits within the seed");
        let counter =
            <&[u8; 4]>::try_from(counter).expect("XChaCha20 counter fits within the seed");
        let counter = u32::from_le_bytes(*counter);
        let mut cipher = Self::new(key, nonce);
        cipher.seek(counter);
        cipher.inner.blocks = u64::MAX;
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

    fn apply_keystream(&mut self, message: &mut [u8]) -> Result<(), Error> {
        self.apply_keystream(message)
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
        let mut state = Secret::from([0u32; 16]);
        state[0..4].copy_from_slice(&Self::SIGMA);
        state[4..12].copy_from_slice(key);
        state[13..16].copy_from_slice(nonce);
        Self {
            state,
            keystream: Secret::from([0u8; 64]),
            offset: 64,
            blocks: 1 << 32,
        }
    }

    fn available(&self) -> u64 {
        self.blocks
            .saturating_mul(64)
            .saturating_add(64 - u64::from(self.offset))
    }

    fn read_nonce(nonce: &[u8; 12]) -> [u32; 3] {
        let mut words = [0u32; 3];
        Self::read(nonce, &mut words);
        words
    }

    fn read(bytes: &[u8], words: &mut [u32]) {
        let (chunks, _) = bytes.as_chunks::<4>();
        for (word, chunk) in words.iter_mut().zip(chunks) {
            *word = u32::from_le_bytes(*chunk);
        }
    }

    fn next(&mut self) {
        let mut block = self.state.clone();
        Self::rounds(block.get_mut());
        for (i, b) in block.get_mut().iter_mut().enumerate() {
            *b = b.wrapping_add(self.state[i]);
        }
        self.state[12] = self.state[12].wrapping_add(1);
        self.blocks = self.blocks.saturating_sub(1);
        let (chunks, _) = self.keystream.as_mut().as_chunks_mut::<4>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&block[i].to_le_bytes());
        }
        self.offset = 0;
    }

    fn next_blocks(&mut self, data: &mut [u8]) {
        let mut initial = Secret::from([[0u32; 4]; 16]);
        for (lanes, &word) in initial.iter_mut().zip(self.state.iter()) {
            *lanes = [word; 4];
        }
        for (lane, counter) in initial[12].iter_mut().enumerate() {
            *counter = counter.wrapping_add(lane as u32);
        }
        let mut blocks = initial.clone();
        Self::rounds(blocks.get_mut());
        let (chunks, _) = data.as_chunks_mut::<4>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            let (lane, word) = (i / 16, i % 16);
            let keystream = blocks[word][lane].wrapping_add(initial[word][lane]);
            for (b, k) in chunk.iter_mut().zip(keystream.to_le_bytes()) {
                *b ^= k;
            }
        }
        self.state[12] = self.state[12].wrapping_add(4);
        self.blocks = self.blocks.saturating_sub(4);
    }

    fn rounds<W>(block: &mut [W; 16])
    where
        W: Word,
    {
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

    fn quarter_round<W>(a: usize, b: usize, c: usize, d: usize, block: &mut [W; 16])
    where
        W: Word,
    {
        block[a] = block[a].add(block[b]);
        block[d] = block[d].xor(block[a]).rotate(16);
        block[c] = block[c].add(block[d]);
        block[b] = block[b].xor(block[c]).rotate(12);
        block[a] = block[a].add(block[b]);
        block[d] = block[d].xor(block[a]).rotate(8);
        block[c] = block[c].add(block[d]);
        block[b] = block[b].xor(block[c]).rotate(7);
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

    fn apply_keystream(&mut self, message: &mut [u8]) -> Result<(), Error> {
        self.apply_keystream(message)
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
        let mut n1 = [0u32; 4];
        let mut n2 = [0u32; 3];
        ChaCha20::read(&nonce[0..16], &mut n1);
        ChaCha20::read(&nonce[16..24], &mut n2[1..]);
        (n1, n2)
    }

    fn calculate_subkey(key: &[u32; 8], nonce: &[u32; 4], subkey: &mut [u32; 8]) {
        let mut state = Secret::from([0u32; 16]);
        state[0..4].copy_from_slice(&ChaCha20::SIGMA);
        state[4..12].copy_from_slice(key);
        state[12..16].copy_from_slice(nonce);
        ChaCha20::rounds(state.get_mut());
        subkey[..4].copy_from_slice(&state[..4]);
        subkey[4..].copy_from_slice(&state[12..]);
    }
}
