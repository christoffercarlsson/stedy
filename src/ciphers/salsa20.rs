use crate::{
    Error,
    traits::{SeekableStreamCipher, StreamCipher},
    utils::{Secret, Word},
};

pub struct Salsa20 {
    state: Secret<[u32; 16]>,
    keystream: Secret<[u8; 64]>,
    offset: u8,
}

impl Salsa20 {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn new(key: &[u8; 32], nonce: &[u8; 8]) -> Self {
        let mut words = Secret::from([0u32; 8]);
        Self::read(key, words.get_mut());
        Self::init(words.get(), Self::read_nonce(*nonce))
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), Error> {
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

pub struct XSalsa20 {
    inner: Salsa20,
}

impl XSalsa20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 24]) -> Self {
        let mut words = Secret::from([0u32; 8]);
        Salsa20::read(key, words.get_mut());
        let (n1, n2) = Self::read_nonce(nonce);
        let mut subkey = Secret::from([0u32; 8]);
        Self::calculate_subkey(words.get(), &n1, subkey.get_mut());
        Self {
            inner: Salsa20::init(subkey.get(), n2),
        }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.inner.apply_keystream(data)
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

impl StreamCipher for Salsa20 {
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 8;

    type Key = [u8; Self::KEY_SIZE];
    type Nonce = [u8; Self::NONCE_SIZE];

    fn new(key: &Self::Key, nonce: &Self::Nonce) -> Self {
        Self::new(key, nonce)
    }

    fn apply_keystream(&mut self, message: &mut [u8]) -> Result<(), Error> {
        self.apply_keystream(message)
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

    fn init(key: &[u32; 8], nonce: [u32; 2]) -> Self {
        let mut state = Secret::from([0u32; 16]);
        Self::state(key, &[nonce[0], nonce[1], 0, 0], state.get_mut());
        Self {
            state,
            keystream: Secret::from([0u8; 64]),
            offset: 64,
        }
    }

    fn state(key: &[u32; 8], nonce: &[u32; 4], state: &mut [u32; 16]) {
        state[0] = Self::SIGMA[0];
        state[5] = Self::SIGMA[1];
        state[10] = Self::SIGMA[2];
        state[15] = Self::SIGMA[3];
        state[1..5].copy_from_slice(&key[0..4]);
        state[11..15].copy_from_slice(&key[4..8]);
        state[6..10].copy_from_slice(nonce);
    }

    fn read_nonce(nonce: [u8; 8]) -> [u32; 2] {
        let mut words = [0u32; 2];
        Self::read(&nonce, &mut words);
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
        let (counter, carry) = self.state[8].overflowing_add(1);
        self.state[8] = counter;
        self.state[9] = self.state[9].wrapping_add(u32::from(carry));
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
        for lane in 0..4 {
            let (counter, carry) = initial[8][lane].overflowing_add(lane as u32);
            initial[8][lane] = counter;
            initial[9][lane] = initial[9][lane].wrapping_add(u32::from(carry));
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
        let (counter, carry) = self.state[8].overflowing_add(4);
        self.state[8] = counter;
        self.state[9] = self.state[9].wrapping_add(u32::from(carry));
    }

    fn rounds<W>(block: &mut [W; 16])
    where
        W: Word,
    {
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

    fn quarter_round<W>(a: usize, b: usize, c: usize, d: usize, block: &mut [W; 16])
    where
        W: Word,
    {
        block[b] = block[b].xor(block[a].add(block[d]).rotate(7));
        block[c] = block[c].xor(block[b].add(block[a]).rotate(9));
        block[d] = block[d].xor(block[c].add(block[b]).rotate(13));
        block[a] = block[a].xor(block[d].add(block[c]).rotate(18));
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

    fn apply_keystream(&mut self, message: &mut [u8]) -> Result<(), Error> {
        self.apply_keystream(message)
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
        let mut n1 = [0u32; 4];
        let mut n2 = [0u32; 2];
        Salsa20::read(&nonce[0..16], &mut n1);
        Salsa20::read(&nonce[16..24], &mut n2);
        (n1, n2)
    }

    fn calculate_subkey(key: &[u32; 8], nonce: &[u32; 4], subkey: &mut [u32; 8]) {
        let mut state = Secret::from([0u32; 16]);
        Salsa20::state(key, nonce, state.get_mut());
        Salsa20::rounds(state.get_mut());
        for (word, i) in subkey.iter_mut().zip([0, 5, 10, 15, 6, 7, 8, 9]) {
            *word = state[i];
        }
    }
}
