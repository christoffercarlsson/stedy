use {
    crate::{
        traits::Wipe,
        utils::{Choice, Secret, unsigned_mul as m},
    },
    core::ops::{AddAssign, BitAndAssign, Index, IndexMut, MulAssign},
};

#[derive(Clone, Copy)]
pub struct Poly1305FieldElement([u64; 3]);

impl Wipe for Poly1305FieldElement {
    fn wipe(&mut self) {
        self.0.wipe();
    }
}

impl Poly1305FieldElement {
    const MASK: u64 = (1 << 44) - 1;
    const TOP_MASK: u64 = (1 << 42) - 1;
    pub const R: Self = Self([0xffc0fffffff, 0xfffffc0ffff, 0xffffffc0f]);
    pub const ZERO: Self = Self([0; 3]);

    fn reduce(&mut self) {
        self.carry();
        let carry = self[2] >> 42;
        self[2] &= Self::TOP_MASK;
        self[0] += carry * 5;
        self[1] += self[0] >> 44;
        self[0] &= Self::MASK;
    }

    fn carry(&mut self) {
        self[1] += self[0] >> 44;
        self[0] &= Self::MASK;
        self[2] += self[1] >> 44;
        self[1] &= Self::MASK;
    }

    pub fn add_truncating(&mut self, rhs: Self) {
        self[0] += rhs[0];
        self[1] += rhs[1];
        self[2] += rhs[2];
        self.carry();
        self[2] &= Self::TOP_MASK;
    }

    pub fn canonical(&mut self) {
        self.reduce();
        self.reduce();
        let mut reduced = *self;
        reduced[0] += 5;
        reduced.carry();
        reduced[2] = reduced[2].wrapping_sub(1 << 42);
        let borrow = Choice::nonzero(reduced[2] >> 63);
        reduced[2] &= Self::TOP_MASK;
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
    }
}

impl BitAndAssign for Poly1305FieldElement {
    fn bitand_assign(&mut self, rhs: Self) {
        self[0] &= rhs[0];
        self[1] &= rhs[1];
        self[2] &= rhs[2];
    }
}

impl MulAssign for Poly1305FieldElement {
    fn mul_assign(&mut self, rhs: Self) {
        let s1 = rhs[1] * 20;
        let s2 = rhs[2] * 20;
        let d0 = m(self[0], rhs[0]) + m(self[1], s2) + m(self[2], s1);
        let d1 = m(self[0], rhs[1]) + m(self[1], rhs[0]) + m(self[2], s2);
        let d2 = m(self[0], rhs[2]) + m(self[1], rhs[1]) + m(self[2], rhs[0]);
        let d1 = d1 + (d0 >> 44);
        let d2 = d2 + (d1 >> 44);
        self[0] = d0 as u64 & Self::MASK;
        self[1] = d1 as u64 & Self::MASK;
        self[2] = d2 as u64 & Self::TOP_MASK;
        self[0] += (d2 >> 42) as u64 * 5;
        self[1] += self[0] >> 44;
        self[0] &= Self::MASK;
    }
}

impl From<&[u8; 17]> for Poly1305FieldElement {
    fn from(value: &[u8; 17]) -> Self {
        let (low, high) = value.split_at(8);
        let low = u64::from_le_bytes(low.try_into().expect("the low half is 8 bytes"));
        let high = u64::from_le_bytes(high[..8].try_into().expect("the high half is 8 bytes"));
        Self([
            low & Self::MASK,
            (low >> 44 | high << 20) & Self::MASK,
            high >> 24 | u64::from(value[16]) << 40,
        ])
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
        (u128::from(fe[0]) | u128::from(fe[1]) << 44 | u128::from(fe[2]) << 88).to_le_bytes()
    }
}
