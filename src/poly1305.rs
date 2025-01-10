use core::ops::{AddAssign, BitAndAssign, MulAssign, Range};

use crate::block::Block;

type Poly1305Block = Block<16>;

const R: u128 = 0x0ffffffc0ffffffc0ffffffc0fffffff;

pub struct Poly1305 {
    a: U130,
    r: U130,
    s: u128,
    block: Poly1305Block,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r = U130::from(&key[0..16]);
        r &= U130::from(R);
        Self {
            a: U130::zero(),
            r,
            s: u128::from_le_bytes(key[16..32].try_into().unwrap()),
            block: Poly1305Block::new(),
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

    pub fn update_padded(&mut self, message: &[u8]) {
        self.update(message);
        let padding = [0u8; 16];
        let padding_size = (16 - (message.len() % 16)) % 16;
        self.update(&padding[..padding_size]);
    }

    fn process_block(&mut self, block: &[u8]) {
        let mut bytes = [0u8; 17];
        bytes[..block.len()].copy_from_slice(block);
        bytes[block.len()] = 1;
        let n = U130::from(bytes);
        self.a += n;
        self.a *= self.r;
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let block = self.block;
        let remaining = block.remaining();
        if !remaining.is_empty() {
            self.process_block(remaining);
        }
        self.a.reduce();
        let a: u128 = self.a.into();
        a.wrapping_add(self.s).to_le_bytes()
    }
}

#[derive(Copy, Clone)]
struct U130 {
    words: [u64; 5],
}

impl U130 {
    const MASK: u64 = (1 << 26) - 1;

    pub fn zero() -> Self {
        Self { words: [0; 5] }
    }

    fn read_word(bytes: &[u8; 17], i: usize) -> u64 {
        let range = Self::get_word_range(i);
        let slice = bytes.get(range).unwrap_or_default();
        let mut word_bytes = [0u8; 4];
        word_bytes[..slice.len()].copy_from_slice(slice);
        u32::from_le_bytes(word_bytes) as u64
    }

    fn get_word_range(i: usize) -> Range<usize> {
        let begin = i * 4;
        let end = (begin + 4).min(17);
        begin..end
    }

    fn write_word(bytes: &mut [u8; 17], i: usize, word: u64) {
        let range = Self::get_word_range(i);
        let slice = bytes.get_mut(range).unwrap_or_default();
        let word_bytes = (word as u32).to_le_bytes();
        slice.copy_from_slice(&word_bytes[..slice.len()]);
    }

    pub fn reduce(&mut self) {
        let mut t = *self;
        t.words[0] += 5;
        t.words[4] = t.words[4].wrapping_sub(1 << 26);
        t.carry();
        let mask = (t.words[4] >> 63).wrapping_sub(1);
        t.mask();
        for i in 0..5 {
            self.words[i] = t.words[i] & mask | self.words[i] & !mask;
        }
    }

    fn carry(&mut self) {
        let mut result = Self::zero();
        let mut carry = 0u64;
        for i in 0..5 {
            let sum = self.words[i].wrapping_add(carry);
            result.words[i] = sum;
            carry = sum >> 26;
        }
        *self = result;
    }

    fn mask(&mut self) {
        for i in 0..5 {
            self.words[i] &= Self::MASK;
        }
    }

    fn to_le_bytes(self) -> [u8; 16] {
        let mut bytes = [0u8; 17];
        let mut carry = 0u64;
        for i in (0..5).rev() {
            let upper_bits = i * 6;
            let lower_bits = (32 - upper_bits) % 32;
            let word = carry | (self.words[i] >> upper_bits);
            carry = self.words[i] << lower_bits;
            U130::write_word(&mut bytes, i, word);
        }
        bytes[..16].try_into().unwrap()
    }
}

impl From<[u8; 17]> for U130 {
    fn from(value: [u8; 17]) -> Self {
        let mut result = Self::zero();
        let mut carry = 0u64;
        for i in 0..5 {
            let word = Self::read_word(&value, i);
            let upper_bits = i * 6;
            let lower_bits = 26 - upper_bits;
            result.words[i] = word << upper_bits | carry;
            carry = word >> lower_bits;
        }
        result.mask();
        result
    }
}

impl From<&[u8]> for U130 {
    fn from(value: &[u8]) -> Self {
        let mut bytes = [0u8; 17];
        bytes[..16].copy_from_slice(value);
        Self::from(bytes)
    }
}

impl From<[u8; 16]> for U130 {
    fn from(value: [u8; 16]) -> Self {
        Self::from(value.as_slice())
    }
}

impl From<u128> for U130 {
    fn from(value: u128) -> Self {
        Self::from(value.to_le_bytes())
    }
}

impl From<U130> for u128 {
    fn from(value: U130) -> u128 {
        u128::from_le_bytes(value.to_le_bytes())
    }
}

impl AddAssign for U130 {
    fn add_assign(&mut self, rhs: Self) {
        for i in 0..5 {
            self.words[i] += rhs.words[i];
        }
    }
}

impl BitAndAssign for U130 {
    fn bitand_assign(&mut self, rhs: Self) {
        for i in 0..5 {
            self.words[i] &= rhs.words[i];
        }
    }
}

impl MulAssign for U130 {
    fn mul_assign(&mut self, rhs: Self) {
        let mut t = Self::zero();
        for i in 0..5 {
            for j in 0..5 {
                let index = i + j;
                let mask = ((index >= 5) as u64).wrapping_neg();
                let factor = (mask & 4) + 1;
                t.words[index % 5] += self.words[i] * rhs.words[j] * factor;
            }
        }
        t.carry();
        self.words = t.words;
        self.mask();
        self.words[0] += (t.words[4] >> 26) * 5;
        self.words[1] += self.words[0] >> 26;
        self.mask();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://datatracker.ietf.org/doc/html/rfc7539#section-2.5.2

    #[test]
    fn test_poly1305() {
        let key = [
            133, 214, 190, 120, 87, 85, 109, 51, 127, 68, 82, 254, 66, 213, 6, 168, 1, 3, 128, 138,
            251, 13, 178, 253, 74, 191, 246, 175, 65, 73, 245, 27,
        ];
        let message = [
            67, 114, 121, 112, 116, 111, 103, 114, 97, 112, 104, 105, 99, 32, 70, 111, 114, 117,
            109, 32, 82, 101, 115, 101, 97, 114, 99, 104, 32, 71, 114, 111, 117, 112,
        ];
        let mut mac = Poly1305::new(&key);
        mac.update(&message);
        let tag = mac.finalize();
        assert_eq!(
            tag,
            [168, 6, 29, 193, 48, 81, 54, 198, 194, 43, 139, 175, 12, 1, 39, 169]
        );
    }

    #[test]
    fn test_u130_from_to() {
        let a = [
            168, 6, 29, 193, 48, 81, 54, 198, 194, 43, 139, 175, 12, 1, 39, 169,
        ];
        let n = U130::from(a);
        assert_eq!(n.to_le_bytes(), a);
        let b = [1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0];
        let n = U130::from(b);
        assert_eq!(n.to_le_bytes(), b);
        let c = [0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4];
        let n = U130::from(c);
        assert_eq!(n.to_le_bytes(), c);
        let d = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let n = U130::from(d);
        assert_eq!(n.to_le_bytes(), d);
    }
}
