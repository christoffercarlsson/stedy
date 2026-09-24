use crate::{utils::Block, Secret};

#[derive(Clone)]
pub struct Sponge<const RATE: usize> {
    lanes: Secret<[u64; 25]>,
    block: Block<RATE>,
}

impl<const RATE: usize> Sponge<RATE> {
    pub fn new() -> Self {
        Self {
            lanes: Secret::from([0u64; 25]),
            block: Block::<RATE>::new(),
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        if let Some((head, tail)) = self.block.blocks(message) {
            self.absorb(&head);
            for block in tail {
                self.absorb(block);
            }
        }
    }

    fn absorb(&mut self, block: &[u8; RATE]) {
        let (chunks, _) = block.as_chunks::<8>();
        for (lane, chunk) in self.lanes.get_mut().iter_mut().zip(chunks.iter()) {
            *lane ^= u64::from_le_bytes(*chunk);
        }
        self.permute();
    }

    pub fn pad(&mut self, domain: u8) {
        let mut block = [0u8; RATE];
        let remaining = self.block.remaining();
        block[..remaining.len()].copy_from_slice(remaining);
        block[remaining.len()] = domain;
        block[RATE - 1] |= 128;
        self.absorb(&block);
    }

    pub fn permute(&mut self) {
        keccak_f1600(self.lanes.get_mut());
    }

    pub fn read(&self, offset: usize, output: &mut [u8]) {
        let mut output = output;
        let mut position = offset;
        while !output.is_empty() {
            let lane = self.lanes[position / 8].to_le_bytes();
            let start = position % 8;
            let take = output.len().min(8 - start);
            let (head, tail) = output.split_at_mut(take);
            head.copy_from_slice(&lane[start..start + take]);
            position += take;
            output = tail;
        }
    }

    pub fn squeeze(&mut self, output: &mut [u8]) {
        for (i, chunk) in output.chunks_mut(RATE).enumerate() {
            if i > 0 {
                self.permute();
            }
            self.read(0, chunk);
        }
    }
}

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

fn keccak_f1600(lanes: &mut [u64; 25]) {
    for &constant in &ROUND_CONSTANTS {
        let c0 = lanes[0] ^ lanes[5] ^ lanes[10] ^ lanes[15] ^ lanes[20];
        let c1 = lanes[1] ^ lanes[6] ^ lanes[11] ^ lanes[16] ^ lanes[21];
        let c2 = lanes[2] ^ lanes[7] ^ lanes[12] ^ lanes[17] ^ lanes[22];
        let c3 = lanes[3] ^ lanes[8] ^ lanes[13] ^ lanes[18] ^ lanes[23];
        let c4 = lanes[4] ^ lanes[9] ^ lanes[14] ^ lanes[19] ^ lanes[24];
        let d0 = c4 ^ c1.rotate_left(1);
        let d1 = c0 ^ c2.rotate_left(1);
        let d2 = c1 ^ c3.rotate_left(1);
        let d3 = c2 ^ c4.rotate_left(1);
        let d4 = c3 ^ c0.rotate_left(1);
        lanes[0] ^= d0;
        lanes[5] ^= d0;
        lanes[10] ^= d0;
        lanes[15] ^= d0;
        lanes[20] ^= d0;
        lanes[1] ^= d1;
        lanes[6] ^= d1;
        lanes[11] ^= d1;
        lanes[16] ^= d1;
        lanes[21] ^= d1;
        lanes[2] ^= d2;
        lanes[7] ^= d2;
        lanes[12] ^= d2;
        lanes[17] ^= d2;
        lanes[22] ^= d2;
        lanes[3] ^= d3;
        lanes[8] ^= d3;
        lanes[13] ^= d3;
        lanes[18] ^= d3;
        lanes[23] ^= d3;
        lanes[4] ^= d4;
        lanes[9] ^= d4;
        lanes[14] ^= d4;
        lanes[19] ^= d4;
        lanes[24] ^= d4;
        let b = [
            lanes[0],
            lanes[6].rotate_left(44),
            lanes[12].rotate_left(43),
            lanes[18].rotate_left(21),
            lanes[24].rotate_left(14),
            lanes[3].rotate_left(28),
            lanes[9].rotate_left(20),
            lanes[10].rotate_left(3),
            lanes[16].rotate_left(45),
            lanes[22].rotate_left(61),
            lanes[1].rotate_left(1),
            lanes[7].rotate_left(6),
            lanes[13].rotate_left(25),
            lanes[19].rotate_left(8),
            lanes[20].rotate_left(18),
            lanes[4].rotate_left(27),
            lanes[5].rotate_left(36),
            lanes[11].rotate_left(10),
            lanes[17].rotate_left(15),
            lanes[23].rotate_left(56),
            lanes[2].rotate_left(62),
            lanes[8].rotate_left(55),
            lanes[14].rotate_left(39),
            lanes[15].rotate_left(41),
            lanes[21].rotate_left(2),
        ];
        lanes[0] = b[0] ^ (!b[1] & b[2]);
        lanes[1] = b[1] ^ (!b[2] & b[3]);
        lanes[2] = b[2] ^ (!b[3] & b[4]);
        lanes[3] = b[3] ^ (!b[4] & b[0]);
        lanes[4] = b[4] ^ (!b[0] & b[1]);
        lanes[5] = b[5] ^ (!b[6] & b[7]);
        lanes[6] = b[6] ^ (!b[7] & b[8]);
        lanes[7] = b[7] ^ (!b[8] & b[9]);
        lanes[8] = b[8] ^ (!b[9] & b[5]);
        lanes[9] = b[9] ^ (!b[5] & b[6]);
        lanes[10] = b[10] ^ (!b[11] & b[12]);
        lanes[11] = b[11] ^ (!b[12] & b[13]);
        lanes[12] = b[12] ^ (!b[13] & b[14]);
        lanes[13] = b[13] ^ (!b[14] & b[10]);
        lanes[14] = b[14] ^ (!b[10] & b[11]);
        lanes[15] = b[15] ^ (!b[16] & b[17]);
        lanes[16] = b[16] ^ (!b[17] & b[18]);
        lanes[17] = b[17] ^ (!b[18] & b[19]);
        lanes[18] = b[18] ^ (!b[19] & b[15]);
        lanes[19] = b[19] ^ (!b[15] & b[16]);
        lanes[20] = b[20] ^ (!b[21] & b[22]);
        lanes[21] = b[21] ^ (!b[22] & b[23]);
        lanes[22] = b[22] ^ (!b[23] & b[24]);
        lanes[23] = b[23] ^ (!b[24] & b[20]);
        lanes[24] = b[24] ^ (!b[20] & b[21]);
        lanes[0] ^= constant;
    }
}
