use core::ops::{AddAssign, BitAndAssign, MulAssign};

use crate::{verify::verify, Error};

#[derive(Clone, Default)]
struct U130 {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub e: u32,
}

impl U130 {
    const MASK: u32 = 0x3ffffff;

    pub fn from_bytes(bytes: &[u8; 16], partial: bool) -> Self {
        let hibit: u32 = if partial { 0 } else { 1 << 24 };
        let a = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) & Self::MASK;
        let b = (u32::from_le_bytes(bytes[3..7].try_into().unwrap()) >> 2) & Self::MASK;
        let c = (u32::from_le_bytes(bytes[6..10].try_into().unwrap()) >> 4) & Self::MASK;
        let d = (u32::from_le_bytes(bytes[9..13].try_into().unwrap()) >> 6) & Self::MASK;
        let e = (u32::from_le_bytes(bytes[12..16].try_into().unwrap()) >> 8) | hibit;
        Self { a, b, c, d, e }
    }

    pub fn reduce(&mut self) {
        let mut carry = self.b >> 26;
        self.b &= Self::MASK;
        self.c += carry;
        carry = self.c >> 26;
        self.c &= Self::MASK;
        self.d += carry;
        carry = self.d >> 26;
        self.d &= Self::MASK;
        self.e += carry;
        carry = self.e >> 26;
        self.e &= Self::MASK;
        self.a += carry * 5;
        carry = self.a >> 26;
        self.a &= Self::MASK;
        self.b += carry;
        let mut g0 = self.a.wrapping_add(5);
        carry = g0 >> 26;
        g0 &= Self::MASK;
        let mut g1 = self.b.wrapping_add(carry);
        carry = g1 >> 26;
        g1 &= Self::MASK;
        let mut g2 = self.c.wrapping_add(carry);
        carry = g2 >> 26;
        g2 &= Self::MASK;
        let mut g3 = self.d.wrapping_add(carry);
        carry = g3 >> 26;
        g3 &= Self::MASK;
        let g4 = self.e.wrapping_add(carry).wrapping_sub(1 << 26);
        let mask = (g4 >> 31).wrapping_sub(1);
        self.a = (self.a & !mask) | (g0 & mask);
        self.b = (self.b & !mask) | (g1 & mask);
        self.c = (self.c & !mask) | (g2 & mask);
        self.d = (self.d & !mask) | (g3 & mask);
        self.e = (self.e & !mask) | (g4 & mask);
    }

    pub fn into_bytes(self) -> [u8; 16] {
        let t0 = self.a | (self.b << 26);
        let t1 = (self.b >> 6) | (self.c << 20);
        let t2 = (self.c >> 12) | (self.d << 14);
        let t3 = (self.d >> 18) | (self.e << 8);
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&t0.to_le_bytes());
        bytes[4..8].copy_from_slice(&t1.to_le_bytes());
        bytes[8..12].copy_from_slice(&t2.to_le_bytes());
        bytes[12..16].copy_from_slice(&t3.to_le_bytes());
        bytes
    }
}

impl AddAssign for U130 {
    fn add_assign(&mut self, rhs: Self) {
        self.a += rhs.a;
        self.b += rhs.b;
        self.c += rhs.c;
        self.d += rhs.d;
        self.e += rhs.e;
    }
}

impl BitAndAssign for U130 {
    fn bitand_assign(&mut self, rhs: Self) {
        self.a &= rhs.a;
        self.b &= rhs.b;
        self.c &= rhs.c;
        self.d &= rhs.d;
        self.e &= rhs.e;
    }
}

impl MulAssign for U130 {
    fn mul_assign(&mut self, rhs: Self) {
        let s1 = rhs.b as u64 * 5;
        let s2 = rhs.c as u64 * 5;
        let s3 = rhs.d as u64 * 5;
        let s4 = rhs.e as u64 * 5;
        let t0 = self.a as u64 * rhs.a as u64
            + self.b as u64 * s4
            + self.c as u64 * s3
            + self.d as u64 * s2
            + self.e as u64 * s1;
        let mut t1 = self.a as u64 * rhs.b as u64
            + self.b as u64 * rhs.a as u64
            + self.c as u64 * s4
            + self.d as u64 * s3
            + self.e as u64 * s2;
        let mut t2 = self.a as u64 * rhs.c as u64
            + self.b as u64 * rhs.b as u64
            + self.c as u64 * rhs.a as u64
            + self.d as u64 * s4
            + self.e as u64 * s3;
        let mut t3 = self.a as u64 * rhs.d as u64
            + self.b as u64 * rhs.c as u64
            + self.c as u64 * rhs.b as u64
            + self.d as u64 * rhs.a as u64
            + self.e as u64 * s4;
        let mut t4 = self.a as u64 * rhs.e as u64
            + self.b as u64 * rhs.d as u64
            + self.c as u64 * rhs.c as u64
            + self.d as u64 * rhs.b as u64
            + self.e as u64 * rhs.a as u64;
        let mut carry = (t0 >> 26) as u32;
        let mut a = t0 as u32 & Self::MASK;
        t1 += carry as u64;
        carry = (t1 >> 26) as u32;
        let mut b = t1 as u32 & Self::MASK;
        t2 += carry as u64;
        carry = (t2 >> 26) as u32;
        let c = t2 as u32 & Self::MASK;
        t3 += carry as u64;
        carry = (t3 >> 26) as u32;
        let d = t3 as u32 & Self::MASK;
        t4 += carry as u64;
        carry = (t4 >> 26) as u32;
        let e = t4 as u32 & Self::MASK;
        a += carry * 5;
        carry = a >> 26;
        a &= Self::MASK;
        b += carry;
        *self = Self { a, b, c, d, e };
    }
}

const R: U130 = U130 {
    a: 0x3ffffff,
    b: 0x3ffff03,
    c: 0x3ffc0ff,
    d: 0x3f03fff,
    e: 0x00fffff,
};

pub struct Poly1305 {
    r: U130,
    s: U130,
    a: U130,
    buffer: [u8; 16],
    buffer_size: usize,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r = U130::from_bytes(key[0..16].try_into().unwrap(), false);
        r &= R;
        let s = U130::from_bytes(key[16..32].try_into().unwrap(), false);
        Self {
            r,
            s,
            a: U130::default(),
            buffer: [0u8; 16],
            buffer_size: 0,
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        let offset = self.process_buffer(message);
        for chunk in message[offset..].chunks(16) {
            if chunk.len() == 16 {
                self.process_block(chunk.try_into().unwrap(), false);
            } else {
                self.buffer_chunk(chunk);
            }
        }
    }

    fn process_buffer(&mut self, message: &[u8]) -> usize {
        let offset = message.len().min(16 - self.buffer_size);
        self.buffer_chunk(&message[..offset]);
        if self.buffer_size == 16 {
            let buffer = self.buffer;
            self.process_block(&buffer, false);
            self.buffer_size = 0;
        }
        offset
    }

    fn buffer_chunk(&mut self, chunk: &[u8]) {
        self.buffer[self.buffer_size..self.buffer_size + chunk.len()].copy_from_slice(chunk);
        self.buffer_size += chunk.len();
    }

    fn process_block(&mut self, block: &[u8; 16], partial: bool) {
        let n = U130::from_bytes(block, partial);
        self.a += n;
        self.a *= self.r.clone();
    }

    pub fn finalize(mut self) -> [u8; 16] {
        if self.buffer_size > 0 {
            let mut block = [0u8; 16];
            block[..self.buffer_size].copy_from_slice(&self.buffer[..self.buffer_size]);
            block[self.buffer_size] = 0x01;
            self.process_block(&block, true);
        }
        self.a += self.s;
        self.a.reduce();
        self.a.into_bytes()
    }

    pub fn verify(self, tag: &[u8; 16]) -> Result<(), Error> {
        verify(&self.finalize(), tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://datatracker.ietf.org/doc/html/rfc7539#section-2.5.2

    #[test]
    fn test_poly1305() {
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let message = [
            0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x20,
            0x46, 0x6f, 0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68,
            0x20, 0x47, 0x72, 0x6f, 0x75, 0x70,
        ];
        let mut mac = Poly1305::new(&key);
        mac.update(&message);
        let tag = mac.finalize();

        let expected = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];

        assert_eq!(tag, expected);
    }
}
