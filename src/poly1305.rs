use core::ops::{AddAssign, BitAndAssign, MulAssign};

use crate::block::Block;

#[derive(Clone, Default)]
struct U130 {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub e: u32,
}

impl U130 {
    const MASK: u32 = 0x03ffffff;

    pub fn from_bytes(bytes: &[u8; 16], partial: bool) -> Self {
        let hibit: u32 = if partial { 0 } else { 1 << 24 };
        let a = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) & Self::MASK;
        let b = u32::from_le_bytes(bytes[3..7].try_into().unwrap()) >> 2 & Self::MASK;
        let c = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) >> 4 & Self::MASK;
        let d = u32::from_le_bytes(bytes[9..13].try_into().unwrap()) >> 6 & Self::MASK;
        let e = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) >> 8 | hibit;
        Self { a, b, c, d, e }
    }

    pub fn reduce(&mut self) {
        self.c += self.b >> 26;
        self.d += self.c >> 26;
        self.e += self.d >> 26;
        self.a += (self.e >> 26) * 5;
        self.b += self.a >> 26;
        self.a &= Self::MASK;
        self.b &= Self::MASK;
        self.c &= Self::MASK;
        self.d &= Self::MASK;
        self.e &= Self::MASK;
        let mut t0 = self.a + 5;
        let mut t1 = (self.b + t0) >> 26;
        let mut t2 = (self.c + t1) >> 26;
        let mut t3 = (self.d + t2) >> 26;
        let t4 = self.e.wrapping_sub(1 << 26).wrapping_add(t3 >> 26);
        t0 &= Self::MASK;
        t1 &= Self::MASK;
        t2 &= Self::MASK;
        t3 &= Self::MASK;
        let mask = (t4 >> 31).wrapping_sub(1);
        self.a = t0 & mask | self.a & !mask;
        self.b = t1 & mask | self.b & !mask;
        self.c = t2 & mask | self.c & !mask;
        self.d = t3 & mask | self.d & !mask;
        self.e = t4 & mask | self.e & !mask;
    }

    pub fn into_32bit_limbs(self) -> [u32; 4] {
        [
            self.a | (self.b << 26),
            (self.b >> 6) | (self.c << 20),
            (self.c >> 12) | (self.d << 14),
            (self.d >> 18) | (self.e << 8),
        ]
    }
}

impl AddAssign for U130 {
    fn add_assign(&mut self, r: Self) {
        self.a += r.a;
        self.b += r.b;
        self.c += r.c;
        self.d += r.d;
        self.e += r.e;
    }
}

impl BitAndAssign for U130 {
    fn bitand_assign(&mut self, r: Self) {
        self.a &= r.a;
        self.b &= r.b;
        self.c &= r.c;
        self.d &= r.d;
        self.e &= r.e;
    }
}

impl MulAssign for U130 {
    fn mul_assign(&mut self, r: Self) {
        let mut t0 = self.a as u64 * r.a as u64;
        let mut t1 = self.b as u64 * r.a as u64;
        let mut t2 = self.c as u64 * r.a as u64;
        let mut t3 = self.d as u64 * r.a as u64;
        let mut t4 = self.e as u64 * r.a as u64;
        t0 += self.e as u64 * r.b as u64 * 5;
        t1 += self.a as u64 * r.b as u64;
        t2 += self.b as u64 * r.b as u64;
        t3 += self.c as u64 * r.b as u64;
        t4 += self.d as u64 * r.b as u64;
        t0 += self.d as u64 * r.c as u64 * 5;
        t1 += self.e as u64 * r.c as u64 * 5;
        t2 += self.a as u64 * r.c as u64;
        t3 += self.b as u64 * r.c as u64;
        t4 += self.c as u64 * r.c as u64;
        t0 += self.c as u64 * r.d as u64 * 5;
        t1 += self.d as u64 * r.d as u64 * 5;
        t2 += self.e as u64 * r.d as u64 * 5;
        t3 += self.a as u64 * r.d as u64;
        t4 += self.b as u64 * r.d as u64;
        t0 += self.b as u64 * r.e as u64 * 5;
        t1 += self.c as u64 * r.e as u64 * 5;
        t2 += self.d as u64 * r.e as u64 * 5;
        t3 += self.e as u64 * r.e as u64 * 5;
        t4 += self.a as u64 * r.e as u64;
        t1 += t0 >> 26;
        t2 += t1 >> 26;
        t3 += t2 >> 26;
        t4 += t3 >> 26;
        let mut a = t0 as u32 & Self::MASK;
        let mut b = t1 as u32 & Self::MASK;
        let c = t2 as u32 & Self::MASK;
        let d = t3 as u32 & Self::MASK;
        let e = t4 as u32 & Self::MASK;
        a += (t4 >> 26) as u32 * 5;
        b += a >> 26;
        a &= Self::MASK;
        *self = Self { a, b, c, d, e };
    }
}

const R: U130 = U130 {
    a: 0x03ffffff,
    b: 0x03ffff03,
    c: 0x03ffc0ff,
    d: 0x03f03fff,
    e: 0x000fffff,
};

type Poly1305Block = Block<16>;

pub struct Poly1305 {
    a: U130,
    r: U130,
    s: [u32; 4],
    block: Poly1305Block,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r = U130::from_bytes(key[0..16].try_into().unwrap(), false);
        r &= R;
        Self {
            a: U130::default(),
            r,
            s: [
                u32::from_le_bytes(key[16..20].try_into().unwrap()),
                u32::from_le_bytes(key[20..24].try_into().unwrap()),
                u32::from_le_bytes(key[24..28].try_into().unwrap()),
                u32::from_le_bytes(key[28..32].try_into().unwrap()),
            ],
            block: Poly1305Block::new(),
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        let (head, tail) = self.block.blocks(message);
        if let Some(head) = head {
            self.process_block(&head, false);
        }
        for (begin, end) in tail {
            self.process_block(&message[begin..end].try_into().unwrap(), false);
        }
    }

    pub fn update_padded(&mut self, message: &[u8]) {
        self.update(message);
        let padding = [0u8; 16];
        let padding_size = (16 - (message.len() % 16)) % 16;
        self.update(&padding[..padding_size]);
    }

    fn process_block(&mut self, block: &[u8; 16], partial: bool) {
        let n = U130::from_bytes(block, partial);
        self.a += n;
        self.a *= self.r.clone();
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let remaining = self.block.remaining();
        if !remaining.is_empty() {
            let mut block = [0u8; 16];
            block[..remaining.len()].copy_from_slice(remaining);
            block[remaining.len()] = 1;
            self.process_block(&block, true);
        }
        self.a.reduce();
        self.calculate_tag()
    }

    fn calculate_tag(self) -> [u8; 16] {
        let a = self.a.into_32bit_limbs();
        let t0 = a[0] as u64 + self.s[0] as u64;
        let mut t1 = a[1] as u64 + self.s[1] as u64;
        let mut t2 = a[2] as u64 + self.s[2] as u64;
        let mut t3 = a[3] as u64 + self.s[3] as u64;
        t1 += t0 >> 32;
        t2 += t1 >> 32;
        t3 += t2 >> 32;
        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&(t0 as u32).to_le_bytes());
        tag[4..8].copy_from_slice(&(t1 as u32).to_le_bytes());
        tag[8..12].copy_from_slice(&(t2 as u32).to_le_bytes());
        tag[12..16].copy_from_slice(&(t3 as u32).to_le_bytes());
        tag
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
