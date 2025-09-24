use crate::block::Block;
use core::ops::{AddAssign, BitAndAssign, Index, IndexMut, MulAssign};

const R: [u8; 16] = [
    255, 255, 255, 15, 252, 255, 255, 15, 252, 255, 255, 15, 252, 255, 255, 15,
];

pub struct Poly1305 {
    a: FieldElement,
    r: FieldElement,
    s: FieldElement,
    block: Block<16>,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r = FieldElement::from(&key[0..16]);
        r &= FieldElement::from(&R);
        Self {
            a: FieldElement::zero(),
            r,
            s: FieldElement::from(&key[16..32]),
            block: Block::<16>::new(),
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
        self.a += FieldElement::from(bytes);
        self.a *= self.r;
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let block = self.block;
        let remaining = block.remaining();
        if !remaining.is_empty() {
            self.process_block(remaining);
        }
        self.a += self.s;
        self.a.into()
    }
}

#[derive(Clone, Copy)]
struct FieldElement([u64; 5]);

impl FieldElement {
    const MASK: u64 = (1u64 << 26) - 1;

    fn zero() -> Self {
        Self([0u64; 5])
    }

    fn reduce(&mut self) {
        let carry = self[4] >> 26;
        self.mask();
        self[0] += carry * 5;
        self[1] += self[0] >> 26;
        self[2] += self[1] >> 26;
        self[0] &= Self::MASK;
        self[1] &= Self::MASK;
    }

    fn carry(&mut self) {
        self[1] += self[0] >> 26;
        self[2] += self[1] >> 26;
        self[3] += self[2] >> 26;
        self[4] += self[3] >> 26;
    }

    fn mask(&mut self) {
        self[0] &= Self::MASK;
        self[1] &= Self::MASK;
        self[2] &= Self::MASK;
        self[3] &= Self::MASK;
        self[4] &= Self::MASK;
    }

    fn canonical(&mut self) {
        let mut reduced = self.clone();
        reduced[0] += 5;
        reduced.carry();
        reduced[4] = reduced[4].wrapping_sub(1 << 26);
        let borrow = reduced[4] >> 63;
        reduced.mask();
        *self = Self::select(&reduced, &self, borrow);
    }

    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        let mask = ((condition != 0) as u64).wrapping_neg();
        Self([
            a[0] & !mask | b[0] & mask,
            a[1] & !mask | b[1] & mask,
            a[2] & !mask | b[2] & mask,
            a[3] & !mask | b[3] & mask,
            a[4] & !mask | b[4] & mask,
        ])
    }
}

impl Index<usize> for FieldElement {
    type Output = u64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for FieldElement {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl AddAssign for FieldElement {
    fn add_assign(&mut self, rhs: Self) {
        self[0] += rhs[0];
        self[1] += rhs[1];
        self[2] += rhs[2];
        self[3] += rhs[3];
        self[4] += rhs[4];
        self.carry();
        self.reduce();
    }
}

impl BitAndAssign for FieldElement {
    fn bitand_assign(&mut self, rhs: Self) {
        self[0] &= rhs[0];
        self[1] &= rhs[1];
        self[2] &= rhs[2];
        self[3] &= rhs[3];
        self[4] &= rhs[4];
    }
}

impl MulAssign for FieldElement {
    fn mul_assign(&mut self, rhs: Self) {
        let mut r = Self::zero();
        r[0] += self[0] * rhs[0];
        r[0] += self[4] * rhs[1] * 5;
        r[0] += self[3] * rhs[2] * 5;
        r[0] += self[2] * rhs[3] * 5;
        r[0] += self[1] * rhs[4] * 5;
        r[1] += self[1] * rhs[0];
        r[1] += self[0] * rhs[1];
        r[1] += self[4] * rhs[2] * 5;
        r[1] += self[3] * rhs[3] * 5;
        r[1] += self[2] * rhs[4] * 5;
        r[2] += self[2] * rhs[0];
        r[2] += self[1] * rhs[1];
        r[2] += self[0] * rhs[2];
        r[2] += self[4] * rhs[3] * 5;
        r[2] += self[3] * rhs[4] * 5;
        r[3] += self[3] * rhs[0];
        r[3] += self[2] * rhs[1];
        r[3] += self[1] * rhs[2];
        r[3] += self[0] * rhs[3];
        r[3] += self[4] * rhs[4] * 5;
        r[4] += self[4] * rhs[0];
        r[4] += self[3] * rhs[1];
        r[4] += self[2] * rhs[2];
        r[4] += self[1] * rhs[3];
        r[4] += self[0] * rhs[4];
        r.carry();
        r.reduce();
        *self = r;
    }
}

impl From<[u64; 5]> for FieldElement {
    fn from(value: [u64; 5]) -> Self {
        let mut result = Self([
            value[0],
            value[0] >> 26 | (value[1] << 6),
            value[1] >> 20 | (value[2] << 12),
            value[2] >> 14 | (value[3] << 18),
            value[3] >> 8 | (value[4] << 24),
        ]);
        result.mask();
        result
    }
}

impl From<[u8; 17]> for FieldElement {
    fn from(value: [u8; 17]) -> Self {
        Self::from([
            u32::from_le_bytes(value[0..4].try_into().unwrap()) as u64,
            u32::from_le_bytes(value[4..8].try_into().unwrap()) as u64,
            u32::from_le_bytes(value[8..12].try_into().unwrap()) as u64,
            u32::from_le_bytes(value[12..16].try_into().unwrap()) as u64,
            value[16] as u64,
        ])
    }
}

impl From<&[u8; 16]> for FieldElement {
    fn from(value: &[u8; 16]) -> Self {
        Self::from(value.as_slice())
    }
}

impl From<&[u8]> for FieldElement {
    fn from(value: &[u8]) -> Self {
        let mut bytes = [0u8; 17];
        bytes[0..16].copy_from_slice(value);
        Self::from(bytes)
    }
}

impl From<FieldElement> for [u32; 4] {
    fn from(mut value: FieldElement) -> Self {
        value.canonical();
        [
            (value[0] | (value[1] << 26)) as u32,
            (value[1] >> 6 | (value[2] << 20)) as u32,
            (value[2] >> 12 | (value[3] << 14)) as u32,
            (value[3] >> 18 | (value[4] << 8)) as u32,
        ]
    }
}

impl From<FieldElement> for [u8; 16] {
    fn from(value: FieldElement) -> Self {
        let result: [u32; 4] = value.into();
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&result[0].to_le_bytes());
        bytes[4..8].copy_from_slice(&result[1].to_le_bytes());
        bytes[8..12].copy_from_slice(&result[2].to_le_bytes());
        bytes[12..16].copy_from_slice(&result[3].to_le_bytes());
        bytes
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
}
