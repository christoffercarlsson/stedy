use crate::Error;

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

    pub fn next(&mut self) -> Result<[u32; 16], Error> {
        if self.state[12] == u32::MAX {
            return Err(Error::LimitExceeded);
        }
        let mut block = self.state;
        for _ in (0..ROUNDS).step_by(2) {
            quarter_round(0, 4, 8, 12, &mut block);
            quarter_round(1, 5, 9, 13, &mut block);
            quarter_round(2, 6, 10, 14, &mut block);
            quarter_round(3, 7, 11, 15, &mut block);
            quarter_round(0, 5, 10, 15, &mut block);
            quarter_round(1, 6, 11, 12, &mut block);
            quarter_round(2, 7, 8, 13, &mut block);
            quarter_round(3, 4, 9, 14, &mut block);
        }
        for (i, b) in block.iter_mut().enumerate() {
            *b = b.wrapping_add(self.state[i]);
        }
        self.state[12] += 1;
        Ok(block)
    }
}

#[inline(always)]
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

pub type ChaCha8 = ChaCha<8>;
pub type ChaCha12 = ChaCha<12>;
pub type ChaCha20 = ChaCha<20>;
