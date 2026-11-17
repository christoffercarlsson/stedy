use {
    crate::{
        traits::Wipe,
        utils::{Choice, Secret},
    },
    core::ops::{AddAssign, BitAndAssign, Index, IndexMut, MulAssign},
};

#[derive(Clone, Copy)]
pub struct Poly1305FieldElement([u64; 5]);

impl Wipe for Poly1305FieldElement {
    fn wipe(&mut self) {
        self.0.wipe();
    }
}

impl Poly1305FieldElement {
    const MASK: u64 = (1 << 26) - 1;
    pub const R: Self = Self([67108863, 67108611, 67092735, 66076671, 1048575]);
    pub const ZERO: Self = Self([0; 5]);

    fn reduce(&mut self) {
        self.carry();
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

    pub fn add_truncating(&mut self, rhs: Self) {
        self[0] += rhs[0];
        self[1] += rhs[1];
        self[2] += rhs[2];
        self[3] += rhs[3];
        self[4] += rhs[4];
        self.carry();
        self.mask();
    }

    pub fn canonical(&mut self) {
        let mut reduced = *self;
        reduced[0] += 5;
        reduced.carry();
        reduced[4] = reduced[4].wrapping_sub(1 << 26);
        let borrow = Choice::nonzero(reduced[4] >> 63);
        reduced.mask();
        borrow.assign(&mut reduced.0, &self.0);
        *self = reduced;
    }
}

impl Index<usize> for Poly1305FieldElement {
    type Output = u64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Poly1305FieldElement {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl AddAssign for Poly1305FieldElement {
    fn add_assign(&mut self, rhs: Self) {
        self[0] += rhs[0];
        self[1] += rhs[1];
        self[2] += rhs[2];
        self[3] += rhs[3];
        self[4] += rhs[4];
        self.reduce();
    }
}

impl BitAndAssign for Poly1305FieldElement {
    fn bitand_assign(&mut self, rhs: Self) {
        self[0] &= rhs[0];
        self[1] &= rhs[1];
        self[2] &= rhs[2];
        self[3] &= rhs[3];
        self[4] &= rhs[4];
    }
}

impl MulAssign for Poly1305FieldElement {
    fn mul_assign(&mut self, rhs: Self) {
        let mut r = Self::ZERO;
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
        r.reduce();
        *self = r;
    }
}

impl From<&[u8; 17]> for Poly1305FieldElement {
    fn from(value: &[u8; 17]) -> Self {
        let mut words = [0u64; 5];
        let (chunks, remainder) = value.as_chunks::<4>();
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u64::from(u32::from_le_bytes(*chunk));
        }
        words[4] = u64::from(remainder[0]);
        let mut fe = Self([
            words[0],
            words[0] >> 26 | (words[1] << 6),
            words[1] >> 20 | (words[2] << 12),
            words[2] >> 14 | (words[3] << 18),
            words[3] >> 8 | (words[4] << 24),
        ]);
        fe.mask();
        fe
    }
}

impl From<&[u8; 16]> for Poly1305FieldElement {
    fn from(value: &[u8; 16]) -> Self {
        let mut bytes = Secret::from([0u8; 17]);
        bytes[..16].copy_from_slice(value);
        Self::from(bytes.get())
    }
}

impl From<Poly1305FieldElement> for [u8; 16] {
    fn from(fe: Poly1305FieldElement) -> Self {
        let words = [
            (fe[0] | (fe[1] << 26)) as u32,
            (fe[1] >> 6 | (fe[2] << 20)) as u32,
            (fe[2] >> 12 | (fe[3] << 14)) as u32,
            (fe[3] >> 18 | (fe[4] << 8)) as u32,
        ];
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&words[0].to_le_bytes());
        bytes[4..8].copy_from_slice(&words[1].to_le_bytes());
        bytes[8..12].copy_from_slice(&words[2].to_le_bytes());
        bytes[12..16].copy_from_slice(&words[3].to_le_bytes());
        bytes
    }
}
