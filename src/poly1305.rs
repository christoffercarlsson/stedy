use crate::block::Block;
use core::ops::{AddAssign, BitAndAssign, MulAssign};

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

    #[inline(always)]
    fn reduce(&mut self) {
        let carry = self.0[4] >> 26;
        self.mask();
        self.0[0] += carry * 5;
        self.0[1] += self.0[0] >> 26;
        self.0[2] += self.0[1] >> 26;
        self.0[0] &= Self::MASK;
        self.0[1] &= Self::MASK;
    }

    #[inline(always)]
    fn carry(&mut self) {
        self.0[1] += self.0[0] >> 26;
        self.0[2] += self.0[1] >> 26;
        self.0[3] += self.0[2] >> 26;
        self.0[4] += self.0[3] >> 26;
    }

    #[inline(always)]
    fn mask(&mut self) {
        self.0[0] &= Self::MASK;
        self.0[1] &= Self::MASK;
        self.0[2] &= Self::MASK;
        self.0[3] &= Self::MASK;
        self.0[4] &= Self::MASK;
    }

    #[inline(always)]
    fn canonical(&mut self) {
        let mut reduced = self.clone();
        reduced.0[0] += 5;
        reduced.carry();
        reduced.0[4] = reduced.0[4].wrapping_sub(1 << 26);
        let borrow = reduced.0[4] >> 63;
        reduced.mask();
        *self = Self::select(&reduced, &self, borrow);
    }

    #[inline(always)]
    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        let mask = condition.wrapping_sub(1);
        Self([
            a.0[0] & mask | b.0[0] & !mask,
            a.0[1] & mask | b.0[1] & !mask,
            a.0[2] & mask | b.0[2] & !mask,
            a.0[3] & mask | b.0[3] & !mask,
            a.0[4] & mask | b.0[4] & !mask,
        ])
    }
}

impl AddAssign for FieldElement {
    fn add_assign(&mut self, rhs: Self) {
        self.0[0] += rhs.0[0];
        self.0[1] += rhs.0[1];
        self.0[2] += rhs.0[2];
        self.0[3] += rhs.0[3];
        self.0[4] += rhs.0[4];
        self.carry();
        self.reduce();
    }
}

impl BitAndAssign for FieldElement {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0[0] &= rhs.0[0];
        self.0[1] &= rhs.0[1];
        self.0[2] &= rhs.0[2];
        self.0[3] &= rhs.0[3];
        self.0[4] &= rhs.0[4];
    }
}

impl MulAssign for FieldElement {
    fn mul_assign(&mut self, rhs: Self) {
        let a = &self.0;
        let b = &rhs.0;
        let mut t = [0u64; 5];
        t[0] = a[0] * b[0];
        t[0] += a[4] * b[1] * 5;
        t[0] += a[3] * b[2] * 5;
        t[0] += a[2] * b[3] * 5;
        t[0] += a[1] * b[4] * 5;
        t[1] = a[1] * b[0];
        t[1] += a[0] * b[1];
        t[1] += a[4] * b[2] * 5;
        t[1] += a[3] * b[3] * 5;
        t[1] += a[2] * b[4] * 5;
        t[2] = a[2] * b[0];
        t[2] += a[1] * b[1];
        t[2] += a[0] * b[2];
        t[2] += a[4] * b[3] * 5;
        t[2] += a[3] * b[4] * 5;
        t[3] = a[3] * b[0];
        t[3] += a[2] * b[1];
        t[3] += a[1] * b[2];
        t[3] += a[0] * b[3];
        t[3] += a[4] * b[4] * 5;
        t[4] = a[4] * b[0];
        t[4] += a[3] * b[1];
        t[4] += a[2] * b[2];
        t[4] += a[1] * b[3];
        t[4] += a[0] * b[4];
        let mut result = Self(t);
        result.carry();
        result.reduce();
        *self = result;
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
        let t = value.0.map(|x| x as u32);
        [
            t[0] | (t[1] << 26),
            t[1] >> 6 | (t[2] << 20),
            t[2] >> 12 | (t[3] << 14),
            t[3] >> 18 | (t[4] << 8),
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
