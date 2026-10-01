use {
    crate::utils::{unsigned_mul as m, Choice},
    core::{
        array::from_fn,
        ops::{Index, IndexMut},
    },
};

#[derive(Clone, Copy)]
pub struct Field448([u32; 16]);

impl Index<usize> for Field448 {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Field448 {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl Field448 {
    pub(super) const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    pub(super) const ZERO: Self = Self([0; 16]);

    pub(crate) const fn from_limbs(value: [u64; 8]) -> Self {
        let mut limbs = [0u32; 16];
        let mut i = 0;
        while i < 8 {
            limbs[2 * i] = (value[i] & Self::MASK as u64) as u32;
            limbs[2 * i + 1] = (value[i] >> 28) as u32;
            i += 1;
        }
        Self(limbs)
    }

    pub(super) fn swap(a: &mut Self, b: &mut Self, condition: Choice) {
        condition.swap(&mut a.0, &mut b.0);
    }

    pub(super) fn select(a: &Self, b: &Self, condition: Choice) -> Self {
        let mut selected = *a;
        condition.assign(&mut selected.0, &b.0);
        selected
    }

    pub(super) fn square(self) -> Self {
        let (a, b) = self.halves();
        let aa = Self::square8(&a);
        let bb = Self::square8(&b);
        let s = Self::square8(&Self::sum8(&a, &b));
        Self::combine(&aa, &bb, &s)
    }

    pub(super) fn mul(self, rhs: Self) -> Self {
        let (a, b) = self.halves();
        let (c, d) = rhs.halves();
        let ac = Self::mul8(&a, &c);
        let bd = Self::mul8(&b, &d);
        let s = Self::mul8(&Self::sum8(&a, &b), &Self::sum8(&c, &d));
        Self::combine(&ac, &bd, &s)
    }

    pub(super) fn add(self, rhs: Self) -> Self {
        let mut result = Self(from_fn(|i| self[i] + rhs[i]));
        result.reduce();
        result
    }

    pub(super) fn sub(self, rhs: Self) -> Self {
        let mut result = Self(from_fn(|i| Self::P2[i] + self[i] - rhs[i]));
        result.reduce();
        result
    }

    pub(super) fn neg(self) -> Self {
        let mut result = Self(from_fn(|i| Self::P2[i] - self[i]));
        result.reduce();
        result
    }

    pub(crate) fn mul_small(self, n: u32) -> Self {
        Self::reduce_wide(from_fn(|i| m(self[i], n)))
    }

    pub(super) fn ct_eq(&self, other: &Self) -> Choice {
        let mut diff = self.sub(*other);
        diff.canonical();
        let result = diff.0.iter().fold(0, |acc, limb| acc | limb);
        !Choice::nonzero(result)
    }

    pub(super) fn from_u32(n: u32) -> Self {
        let mut result = Self::ZERO;
        result[0] = n & Self::MASK;
        result[1] = n >> 28;
        result
    }

    pub(crate) fn from_le_bytes(bytes: &[u8; 56]) -> Self {
        let mut result = Self::ZERO;
        for (i, chunk) in bytes.chunks(7).enumerate() {
            let mut word = [0u8; 8];
            word[..7].copy_from_slice(chunk);
            let word = u64::from_le_bytes(word);
            result[2 * i] = (word & Self::MASK as u64) as u32;
            result[2 * i + 1] = (word >> 28) as u32;
        }
        result
    }

    pub(crate) fn to_le_bytes(mut self) -> [u8; 56] {
        self.canonical();
        let mut bytes = [0u8; 56];
        for (i, chunk) in bytes.chunks_mut(7).enumerate() {
            let word = self[2 * i] as u64 | ((self[2 * i + 1] as u64) << 28);
            chunk.copy_from_slice(&word.to_le_bytes()[..7]);
        }
        bytes
    }
}

impl Field448 {
    const MASK: u32 = (1 << 28) - 1;
    const P: Self = Self([
        Self::MASK,
        Self::MASK,
        Self::MASK,
        Self::MASK,
        Self::MASK,
        Self::MASK,
        Self::MASK,
        Self::MASK,
        Self::MASK - 1,
        Self::MASK,
        Self::MASK,
        Self::MASK,
        Self::MASK,
        Self::MASK,
        Self::MASK,
        Self::MASK,
    ]);
    const P2: Self = Self([
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        (Self::MASK << 1) - 2,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
    ]);

    fn halves(&self) -> ([u32; 8], [u32; 8]) {
        (from_fn(|i| self[i]), from_fn(|i| self[8 + i]))
    }

    fn sum8(a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
        from_fn(|i| a[i] + b[i])
    }

    fn mul8(a: &[u32; 8], b: &[u32; 8]) -> [u64; 15] {
        let mut t = [0u64; 15];
        for i in 0..8 {
            for j in 0..8 {
                t[i + j] += m(a[i], b[j]);
            }
        }
        t
    }

    fn square8(a: &[u32; 8]) -> [u64; 15] {
        let mut t = [0u64; 15];
        for i in 0..8 {
            t[2 * i] += m(a[i], a[i]);
            let a2 = a[i] * 2;
            for j in (i + 1)..8 {
                t[i + j] += m(a2, a[j]);
            }
        }
        t
    }

    fn combine(ac: &[u64; 15], bd: &[u64; 15], s: &[u64; 15]) -> Self {
        let lo = |k: usize| ac[k] + bd[k];
        let hi = |k: usize| s[k] - ac[k];
        let mut t = [0u64; 16];
        for j in 0..7 {
            t[j] = lo(j) + hi(8 + j);
            t[8 + j] = lo(8 + j) + hi(j) + hi(8 + j);
        }
        t[7] = lo(7);
        t[15] = hi(7);
        Self::reduce_wide(t)
    }

    fn reduce_wide(mut t: [u64; 16]) -> Self {
        for i in 0..15 {
            t[i + 1] += t[i] >> 28;
        }
        let carry = t[15] >> 28;
        for limb in t.iter_mut() {
            *limb &= Self::MASK as u64;
        }
        t[0] += carry;
        t[8] += carry;
        for i in 0..15 {
            t[i + 1] += t[i] >> 28;
        }
        let carry = t[15] >> 28;
        let mut result = Self(from_fn(|i| (t[i] as u32) & Self::MASK));
        result[0] += carry as u32;
        result[8] += carry as u32;
        result
    }

    fn reduce(&mut self) {
        self.carry();
        let carry = self[15] >> 28;
        self.mask();
        self[0] += carry;
        self[8] += carry;
    }

    fn carry(&mut self) {
        for i in 0..15 {
            self[i + 1] += self[i] >> 28;
        }
    }

    fn mask(&mut self) {
        for i in 0..16 {
            self[i] &= Self::MASK;
        }
    }

    fn canonical(&mut self) {
        self.reduce();
        let mut borrow = 0i64;
        for i in 0..16 {
            let t = self[i] as i64 - Self::P[i] as i64 - borrow;
            self[i] = (t as u32) & Self::MASK;
            borrow = (t >> 63) & 1;
        }
        let add_back = Choice::nonzero(borrow as u32).mask::<u32>();
        let mut carry = 0;
        for i in 0..16 {
            let t = self[i] + (Self::P[i] & add_back) + carry;
            self[i] = t & Self::MASK;
            carry = t >> 28;
        }
    }
}
