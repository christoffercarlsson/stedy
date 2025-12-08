pub struct ChaCha<const ROUNDS: u8> {
    state: [u32; 16],
    keystream: [u8; 64],
    offset: usize,
}

impl<const ROUNDS: u8> ChaCha<ROUNDS> {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&Self::SIGMA);
        state[4..12].copy_from_slice(&Self::read_key(key));
        state[13..16].copy_from_slice(&Self::read_nonce(nonce));
        Self {
            state,
            keystream: [0u8; 64],
            offset: 64,
        }
    }

    pub fn apply_keystream(&mut self, mut data: &mut [u8]) {
        while !data.is_empty() {
            if self.offset == 64 {
                self.next();
            }
            let take = data.len().min(64 - self.offset);
            let keystream = &self.keystream[self.offset..self.offset + take];
            let (head, tail) = data.split_at_mut(take);
            for (b, k) in head.iter_mut().zip(keystream.iter()) {
                *b ^= k;
            }
            self.offset += take;
            data = tail;
        }
    }

    pub fn seek(&mut self, counter: u32) {
        self.state[12] = counter;
        self.offset = 64;
    }
}

impl<const ROUNDS: u8> ChaCha<ROUNDS> {
    const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

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
        for _ in (0..ROUNDS).step_by(2) {
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

impl<const ROUNDS: u8> From<&[u8; 32]> for ChaCha<ROUNDS> {
    fn from(key: &[u8; 32]) -> Self {
        Self::new(key, &[0u8; 12])
    }
}

impl<const ROUNDS: u8> From<&[u8; 48]> for ChaCha<ROUNDS> {
    fn from(seed: &[u8; 48]) -> Self {
        let key: &[u8; 32] = seed[0..32].try_into().unwrap();
        let nonce: &[u8; 12] = seed[32..44].try_into().unwrap();
        let counter = u32::from_le_bytes(seed[44..48].try_into().unwrap());
        let mut cipher = Self::new(key, nonce);
        cipher.seek(counter);
        cipher
    }
}

// pub type ChaCha8 = ChaCha<8>;
// pub type ChaCha12 = ChaCha<12>;
pub type ChaCha20 = ChaCha<20>;
