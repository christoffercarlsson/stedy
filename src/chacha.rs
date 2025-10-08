const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

pub struct ChaCha<const ROUNDS: u8> {
    state: [u32; 16],
}

impl<const ROUNDS: u8> ChaCha<ROUNDS> {
    pub fn new(key: &[u32; 8], nonce: &[u32; 3]) -> Self {
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&SIGMA);
        state[4..12].copy_from_slice(key);
        state[13..16].copy_from_slice(nonce);
        Self { state }
    }

    pub fn from(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let k = Self::read_key(key);
        let n = Self::read_nonce(nonce);
        Self::new(&k, &n)
    }

    fn read_key(key: &[u8; 32]) -> [u32; 8] {
        [
            u32::from_le_bytes(key[0..4].try_into().unwrap()),
            u32::from_le_bytes(key[4..8].try_into().unwrap()),
            u32::from_le_bytes(key[8..12].try_into().unwrap()),
            u32::from_le_bytes(key[12..16].try_into().unwrap()),
            u32::from_le_bytes(key[16..20].try_into().unwrap()),
            u32::from_le_bytes(key[20..24].try_into().unwrap()),
            u32::from_le_bytes(key[24..28].try_into().unwrap()),
            u32::from_le_bytes(key[28..32].try_into().unwrap()),
        ]
    }

    fn read_nonce(nonce: &[u8; 12]) -> [u32; 3] {
        [
            u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
            u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
            u32::from_le_bytes(nonce[8..12].try_into().unwrap()),
        ]
    }

    fn block(&mut self) -> [u32; 16] {
        let mut block = self.state;
        Self::rounds(&mut block);
        for (i, b) in block.iter_mut().enumerate() {
            *b = b.wrapping_add(self.state[i]);
        }
        self.state[12] = self.state[12].wrapping_add(1);
        block
    }

    fn rounds(block: &mut [u32; 16]) {
        for _ in (0..ROUNDS).step_by(2) {
            quarter_round(0, 4, 8, 12, block);
            quarter_round(1, 5, 9, 13, block);
            quarter_round(2, 6, 10, 14, block);
            quarter_round(3, 7, 11, 15, block);
            quarter_round(0, 5, 10, 15, block);
            quarter_round(1, 6, 11, 12, block);
            quarter_round(2, 7, 8, 13, block);
            quarter_round(3, 4, 9, 14, block);
        }
    }

    fn next(&mut self) -> [u8; 64] {
        let mut keystream = [0u8; 64];
        for (i, word) in self.block().iter().enumerate() {
            let begin = i * 4;
            let end = begin + 4;
            keystream[begin..end].copy_from_slice(&word.to_le_bytes());
        }
        keystream
    }

    pub fn apply_keystream(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(64) {
            let keystream = self.next();
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }
        }
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

// pub type ChaCha8 = ChaCha<8>;
// pub type ChaCha12 = ChaCha<12>;
pub type ChaCha20 = ChaCha<20>;

pub struct XChaCha20;

impl XChaCha20 {
    pub fn from(key: &[u8; 32], nonce: &[u8; 24]) -> ChaCha20 {
        let k = ChaCha20::read_key(key);
        let (n1, n2) = Self::read_nonce(nonce);
        let subkey = Self::calculate_subkey(&k, &n1);
        ChaCha20::new(&subkey, &n2)
    }

    fn read_nonce(nonce: &[u8; 24]) -> ([u32; 4], [u32; 3]) {
        let n1 = [
            u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
            u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
            u32::from_le_bytes(nonce[8..12].try_into().unwrap()),
            u32::from_le_bytes(nonce[12..16].try_into().unwrap()),
        ];
        let n2 = [
            0,
            u32::from_le_bytes(nonce[16..20].try_into().unwrap()),
            u32::from_le_bytes(nonce[20..24].try_into().unwrap()),
        ];
        (n1, n2)
    }

    fn calculate_subkey(key: &[u32; 8], nonce: &[u32; 4]) -> [u32; 8] {
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&SIGMA);
        state[4..12].copy_from_slice(key);
        state[12..16].copy_from_slice(nonce);
        ChaCha20::rounds(&mut state);
        [
            state[0], state[1], state[2], state[3], state[12], state[13], state[14], state[15],
        ]
    }
}
