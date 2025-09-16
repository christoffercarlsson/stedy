use core::ops::{Add, AddAssign, Div, Mul, MulAssign, Sub};

#[derive(Clone, Copy)]
pub struct Curve25519([u64; 5]);

impl Curve25519 {
    const MASK: u64 = (1u64 << 51) - 1;

    pub fn zero() -> Self {
        Self([0; 5])
    }

    pub fn one() -> Self {
        Self([1, 0, 0, 0, 0])
    }

    pub fn select(a: &Self, b: &Self, condition: u64) -> Self {
        let mut x = *a;
        let mut y = *b;
        Self::swap(&mut x, &mut y, condition);
        x
    }

    pub fn swap(a: &mut Self, b: &mut Self, condition: u64) {
        let mask = ((condition != 0) as u64).wrapping_neg();
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    pub fn add(self, rhs: Self) -> Self {
        Self::from([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ])
    }

    pub fn sub(self, rhs: Self) -> Self {
        Self::from([
            4503599627370458 + self.0[0] - rhs.0[0],
            4503599627370494 + self.0[1] - rhs.0[1],
            4503599627370494 + self.0[2] - rhs.0[2],
            4503599627370494 + self.0[3] - rhs.0[3],
            4503599627370494 + self.0[4] - rhs.0[4],
        ])
    }

    pub fn mul(self, rhs: Self) -> Self {
        let a = &self.0;
        let b = &rhs.0;
        let mut t = [0u128; 5];
        t[0] = m(a[0], b[0]);
        t[0] += m(a[4], b[1] * 19);
        t[0] += m(a[3], b[2] * 19);
        t[0] += m(a[2], b[3] * 19);
        t[0] += m(a[1], b[4] * 19);
        t[1] = m(a[1], b[0]);
        t[1] += m(a[0], b[1]);
        t[1] += m(a[4], b[2] * 19);
        t[1] += m(a[3], b[3] * 19);
        t[1] += m(a[2], b[4] * 19);
        t[2] = m(a[2], b[0]);
        t[2] += m(a[1], b[1]);
        t[2] += m(a[0], b[2]);
        t[2] += m(a[4], b[3] * 19);
        t[2] += m(a[3], b[4] * 19);
        t[3] = m(a[3], b[0]);
        t[3] += m(a[2], b[1]);
        t[3] += m(a[1], b[2]);
        t[3] += m(a[0], b[3]);
        t[3] += m(a[4], b[4] * 19);
        t[4] = m(a[4], b[0]);
        t[4] += m(a[3], b[1]);
        t[4] += m(a[2], b[2]);
        t[4] += m(a[1], b[3]);
        t[4] += m(a[0], b[4]);
        Self::from(t)
    }

    pub fn square(self) -> Self {
        let a = &self.0;
        let mut t = [0u128; 5];
        t[0] = m(a[0], a[0]);
        t[0] += 2 * (m(a[1], a[4] * 19) + m(a[2], a[3] * 19));
        t[1] = m(a[3], a[3] * 19);
        t[1] += 2 * (m(a[0], a[1]) + m(a[2], a[4] * 19));
        t[2] += m(a[1], a[1]);
        t[2] += 2 * (m(a[0], a[2]) + m(a[4], a[3] * 19));
        t[3] = m(a[4], a[4] * 19);
        t[3] += 2 * (m(a[0], a[3]) + m(a[1], a[2]));
        t[4] = m(a[2], a[2]);
        t[4] += 2 * (m(a[0], a[4]) + m(a[1], a[3]));
        Self::from(t)
    }

    pub fn div(self, rhs: Self) -> Self {
        self.mul(rhs.invert())
    }

    #[inline(always)]
    fn invert(self) -> Self {
        let mut a = self.square();
        let mut b = a.square();
        b = b.square();
        b = self.mul(b);
        a = a.mul(b);
        let mut c = a.square();
        b = b.mul(c);
        c = b;
        for _ in 0..5 {
            c = c.square();
        }
        b = c.mul(b);
        c = b;
        for _ in 0..10 {
            c = c.square();
        }
        c = c.mul(b);
        let mut d = c;
        for _ in 0..20 {
            d = d.square();
        }
        c = d.mul(c);
        for _ in 0..10 {
            c = c.square();
        }
        b = c.mul(b);
        c = b;
        for _ in 0..50 {
            c = c.square();
        }
        c = c.mul(b);
        d = c;
        for _ in 0..100 {
            d = d.square();
        }
        c = d.mul(c);
        for _ in 0..50 {
            c = c.square();
        }
        b = c.mul(b);
        for _ in 0..5 {
            b = b.square();
        }
        b.mul(a)
    }

    #[inline(always)]
    fn reduce(&mut self) {
        let carry = self.0[4] >> 51;
        self.mask();
        self.0[0] += carry * 19;
        self.0[1] += self.0[0] >> 51;
        self.0[2] += self.0[1] >> 51;
        self.0[0] &= Self::MASK;
        self.0[1] &= Self::MASK;
    }

    #[inline(always)]
    fn carry(&mut self) {
        self.0[1] += self.0[0] >> 51;
        self.0[2] += self.0[1] >> 51;
        self.0[3] += self.0[2] >> 51;
        self.0[4] += self.0[3] >> 51;
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
        reduced.0[0] += 19;
        reduced.carry();
        reduced.0[4] = reduced.0[4].wrapping_sub(1 << 51);
        let borrow = reduced.0[4] >> 63;
        reduced.mask();
        *self = Self::select(&reduced, &self, borrow);
    }
}

#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    (x as u128) * (y as u128)
}

impl Add for Curve25519 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl AddAssign for Curve25519 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Div for Curve25519 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.div(rhs)
    }
}

impl Mul for Curve25519 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl MulAssign for Curve25519 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl Sub for Curve25519 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(rhs)
    }
}

impl From<[u128; 5]> for Curve25519 {
    fn from(mut value: [u128; 5]) -> Self {
        value[1] += ((value[0] >> 51) as u64) as u128;
        value[2] += ((value[1] >> 51) as u64) as u128;
        value[3] += ((value[2] >> 51) as u64) as u128;
        value[4] += ((value[3] >> 51) as u64) as u128;
        let carry = (value[4] >> 51) as u64;
        let mut t = [
            (value[0] as u64) & Self::MASK,
            (value[1] as u64) & Self::MASK,
            (value[2] as u64) & Self::MASK,
            (value[3] as u64) & Self::MASK,
            (value[4] as u64) & Self::MASK,
        ];
        t[0] += carry * 19;
        t[1] += t[0] >> 51;
        t[2] += t[1] >> 51;
        t[0] &= Self::MASK;
        t[1] &= Self::MASK;
        Self(t)
    }
}

impl From<[u64; 5]> for Curve25519 {
    fn from(value: [u64; 5]) -> Self {
        let mut result = Self(value);
        result.carry();
        result.reduce();
        result
    }
}

impl From<u64> for Curve25519 {
    fn from(value: u64) -> Self {
        Self::from([value, 0, 0, 0, 0])
    }
}

impl From<u32> for Curve25519 {
    fn from(value: u32) -> Self {
        Self::from(value as u64)
    }
}

impl From<[u64; 4]> for Curve25519 {
    fn from(value: [u64; 4]) -> Self {
        let mut result = Self::zero();
        result.0[0] = value[0];
        result.0[1] = (value[0] >> 51) | (value[1] << 13);
        result.0[2] = (value[1] >> 38) | (value[2] << 26);
        result.0[3] = (value[2] >> 25) | (value[3] << 39);
        result.0[4] = value[3] >> 12;
        result.mask();
        result
    }
}

impl From<&[u8]> for Curve25519 {
    fn from(value: &[u8]) -> Self {
        Self::from([
            u64::from_le_bytes(value[0..8].try_into().unwrap()),
            u64::from_le_bytes(value[8..16].try_into().unwrap()),
            u64::from_le_bytes(value[16..24].try_into().unwrap()),
            u64::from_le_bytes(value[24..32].try_into().unwrap()),
        ])
    }
}

impl From<&[u8; 32]> for Curve25519 {
    fn from(value: &[u8; 32]) -> Self {
        Self::from(value.as_slice())
    }
}

impl From<Curve25519> for [u64; 4] {
    fn from(mut value: Curve25519) -> Self {
        value.canonical();
        let t = &value.0;
        [
            t[0] | (t[1] << 51),
            t[1] >> 13 | (t[2] << 38),
            t[2] >> 26 | (t[3] << 25),
            t[3] >> 39 | (t[4] << 12),
        ]
    }
}

impl From<Curve25519> for [u8; 32] {
    fn from(value: Curve25519) -> Self {
        let result: [u64; 4] = value.into();
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&result[0].to_le_bytes());
        bytes[8..16].copy_from_slice(&result[1].to_le_bytes());
        bytes[16..24].copy_from_slice(&result[2].to_le_bytes());
        bytes[24..32].copy_from_slice(&result[3].to_le_bytes());
        bytes
    }
}
