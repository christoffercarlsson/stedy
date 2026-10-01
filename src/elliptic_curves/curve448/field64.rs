use {
    crate::utils::{unsigned_mul as m, Choice},
    core::{
        array::from_fn,
        ops::{Index, IndexMut},
    },
};

#[derive(Clone, Copy)]
pub struct Field448([u64; 8]);

impl Index<usize> for Field448 {
    type Output = u64;

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
    pub(super) const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0]);
    pub(super) const ZERO: Self = Self([0; 8]);

    pub(crate) const fn from_limbs(value: [u64; 8]) -> Self {
        Self(value)
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
        let aa = Self::square4(&a);
        let bb = Self::square4(&b);
        let s = Self::square4(&Self::sum4(&a, &b));
        Self::combine(&aa, &bb, &s)
    }

    pub(super) fn mul(self, rhs: Self) -> Self {
        let (a, b) = self.halves();
        let (c, d) = rhs.halves();
        let ac = Self::mul4(&a, &c);
        let bd = Self::mul4(&b, &d);
        let s = Self::mul4(&Self::sum4(&a, &b), &Self::sum4(&c, &d));
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
        Self::reduce_wide(from_fn(|i| m(self[i], n as u64)))
    }

    pub(super) fn ct_eq(&self, other: &Self) -> Choice {
        let mut diff = self.sub(*other);
        diff.canonical();
        let result = diff.0.iter().fold(0, |acc, limb| acc | limb);
        !Choice::nonzero(result)
    }

    pub(super) fn from_u32(n: u32) -> Self {
        let mut result = Self::ZERO;
        result[0] = n as u64;
        result
    }

    pub(crate) fn from_le_bytes(bytes: &[u8; 56]) -> Self {
        let mut result = Self::ZERO;
        for (i, chunk) in bytes.chunks(7).enumerate() {
            let mut word = [0u8; 8];
            word[..7].copy_from_slice(chunk);
            result[i] = u64::from_le_bytes(word);
        }
        result
    }

    pub(crate) fn to_le_bytes(mut self) -> [u8; 56] {
        self.canonical();
        let mut bytes = [0u8; 56];
        for (i, chunk) in bytes.chunks_mut(7).enumerate() {
            chunk.copy_from_slice(&self[i].to_le_bytes()[..7]);
        }
        bytes
    }
}

impl Field448 {
    const MASK: u64 = (1 << 56) - 1;
    const P: Self = Self([
        Self::MASK,
        Self::MASK,
        Self::MASK,
        Self::MASK,
        Self::MASK - 1,
        Self::MASK,
        Self::MASK,
        Self::MASK,
    ]);
    const P2: Self = Self([
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
        (Self::MASK << 1) - 2,
        Self::MASK << 1,
        Self::MASK << 1,
        Self::MASK << 1,
    ]);

    fn halves(&self) -> ([u64; 4], [u64; 4]) {
        (
            [self[0], self[1], self[2], self[3]],
            [self[4], self[5], self[6], self[7]],
        )
    }

    fn sum4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        from_fn(|i| a[i] + b[i])
    }

    fn mul4(a: &[u64; 4], b: &[u64; 4]) -> [u128; 7] {
        let mut t = [0u128; 7];
        for i in 0..4 {
            for j in 0..4 {
                t[i + j] += m(a[i], b[j]);
            }
        }
        t
    }

    fn square4(a: &[u64; 4]) -> [u128; 7] {
        let a0_2 = a[0] * 2;
        let a1_2 = a[1] * 2;
        let a2_2 = a[2] * 2;
        [
            m(a[0], a[0]),
            m(a0_2, a[1]),
            m(a0_2, a[2]) + m(a[1], a[1]),
            m(a0_2, a[3]) + m(a1_2, a[2]),
            m(a1_2, a[3]) + m(a[2], a[2]),
            m(a2_2, a[3]),
            m(a[3], a[3]),
        ]
    }

    fn combine(ac: &[u128; 7], bd: &[u128; 7], s: &[u128; 7]) -> Self {
        let lo = |k: usize| ac[k] + bd[k];
        let hi = |k: usize| s[k] - ac[k];
        Self::reduce_wide([
            lo(0) + hi(4),
            lo(1) + hi(5),
            lo(2) + hi(6),
            lo(3),
            lo(4) + hi(0) + hi(4),
            lo(5) + hi(1) + hi(5),
            lo(6) + hi(2) + hi(6),
            hi(3),
        ])
    }

    fn reduce_wide(mut t: [u128; 8]) -> Self {
        for i in 0..7 {
            t[i + 1] += t[i] >> 56;
        }
        let carry = (t[7] >> 56) as u64;
        let mut result = Self(from_fn(|i| (t[i] as u64) & Self::MASK));
        result[0] += carry;
        result[4] += carry;
        result.reduce();
        result
    }

    fn reduce(&mut self) {
        self.carry();
        let carry = self[7] >> 56;
        self.mask();
        self[0] += carry;
        self[4] += carry;
    }

    fn carry(&mut self) {
        for i in 0..7 {
            self[i + 1] += self[i] >> 56;
        }
    }

    fn mask(&mut self) {
        for i in 0..8 {
            self[i] &= Self::MASK;
        }
    }

    fn canonical(&mut self) {
        self.reduce();
        let mut borrow = 0i64;
        for i in 0..8 {
            let t = self[i] as i64 - Self::P[i] as i64 - borrow;
            self[i] = (t as u64) & Self::MASK;
            borrow = (t >> 63) & 1;
        }
        let add_back = Choice::nonzero(borrow as u64).mask::<u64>();
        let mut carry = 0;
        for i in 0..8 {
            let t = self[i] + (Self::P[i] & add_back) + carry;
            self[i] = t & Self::MASK;
            carry = t >> 56;
        }
    }
}
