use {
    crate::{
        curve25519::Curve25519,
        scalar25519::Scalar25519,
        traits::{EdwardsPoint, FieldElement},
    },
    core::ops::{Add, Index, Mul, Neg},
};

#[derive(Clone, Copy)]
pub struct Edwards25519 {
    x: Curve25519,
    y: Curve25519,
    t: Curve25519,
    z: Curve25519,
}

impl EdwardsPoint<Curve25519, Scalar25519> for Edwards25519 {
    const BASE_POINT: Self = Self {
        x: Curve25519([
            1738742601995546,
            1146398526822698,
            2070867633025821,
            562264141797630,
            587772402128613,
        ]),
        y: Curve25519([
            1801439850948184,
            1351079888211148,
            450359962737049,
            900719925474099,
            1801439850948198,
        ]),
        z: Curve25519::ONE,
        t: Curve25519([
            1841354044333475,
            16398895984059,
            755974180946558,
            900171276175154,
            1821297809914039,
        ]),
    };
    const IDENTITY: Self = Self {
        x: Curve25519::ZERO,
        y: Curve25519::ONE,
        z: Curve25519::ONE,
        t: Curve25519::ZERO,
    };

    fn decompress(scalar: &[u8; 32]) -> (Self, u64) {
        let sign = (scalar[31] >> 7) as u64;
        let mut bytes = *scalar;
        bytes[31] &= 127;
        let y = Curve25519::from(&bytes);
        let y2 = y.square();
        let u = y2 - Curve25519::ONE;
        let v = Self::D * y2 + Curve25519::ONE;
        let (mut x, mut valid) = u.sqrt(v);
        let is_zero = (x == Curve25519::ZERO) as u64;
        valid &= (is_zero & sign) ^ 1;
        let xs: [u8; 32] = x.into();
        let negate = (xs[0] as u64 & 1) ^ sign;
        x = Curve25519::select(&x, &x.neg(), negate);
        let point = Self {
            x,
            y,
            t: x * y,
            z: Curve25519::ONE,
        };
        (point, valid)
    }

    fn compress(self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x * zi;
        let y = self.y * zi;
        let xs: [u8; 32] = x.into();
        let mut ys: [u8; 32] = y.into();
        let sign = xs[0] & 1;
        ys[31] &= 127;
        ys[31] |= sign << 7;
        ys
    }
}

impl Edwards25519 {
    const D: Curve25519 = Curve25519([
        929955233495203,
        466365720129213,
        1662059464998953,
        2033849074728123,
        1442794654840575,
    ]);
    const D2: Curve25519 = Curve25519([
        1859910466990425,
        932731440258426,
        1072319116312658,
        1815898335770999,
        633789495995903,
    ]);

    fn double(self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let z2 = self.z.square();
        let c = z2 + z2;
        let e = (self.x + self.y).square() - a - b;
        let g = b - a;
        let f = g - c;
        let h = Curve25519::ZERO - (a + b);
        let x = e * f;
        let y = g * h;
        let t = e * h;
        let z = f * g;
        Self { x, y, t, z }
    }

    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        Self {
            x: Curve25519::select(&a.x, &b.x, condition),
            y: Curve25519::select(&a.y, &b.y, condition),
            t: Curve25519::select(&a.t, &b.t, condition),
            z: Curve25519::select(&a.z, &b.z, condition),
        }
    }
}

impl PartialEq for Edwards25519 {
    fn eq(&self, other: &Self) -> bool {
        (self.x * other.z) == (other.x * self.z)
    }
}

impl Eq for Edwards25519 {}

impl Add for Edwards25519 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let a = (self.y - self.x) * (rhs.y - rhs.x);
        let b = (self.y + self.x) * (rhs.y + rhs.x);
        let c = self.t * Self::D2 * rhs.t;
        let d = (self.z + self.z) * rhs.z;
        let e = b - a;
        let f = d - c;
        let g = d + c;
        let h = b + a;
        let x = e * f;
        let y = g * h;
        let t = e * h;
        let z = f * g;
        Self { x, y, t, z }
    }
}

impl Mul<Scalar25519> for Edwards25519 {
    type Output = Self;

    fn mul(self, rhs: Scalar25519) -> Self::Output {
        let window = Window::from(self);
        let digits = rhs.as_radix_16();
        let mut q = window.select(digits[63]);
        for i in (0..63).rev() {
            q = q.double();
            q = q.double();
            q = q.double();
            q = q.double();
            q = q + window.select(digits[i]);
        }
        q
    }
}

impl Neg for Edwards25519 {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            t: self.t.neg(),
            z: self.z,
        }
    }
}

struct Window([Edwards25519; 9]);

impl Window {
    fn select(&self, x: i8) -> Edwards25519 {
        let y = x as i16;
        let z = y >> 15;
        let i = ((y ^ z) - z) as u8;
        let mut t = Edwards25519::IDENTITY;
        for j in 0..9 {
            let is_index = ((j ^ i) == 0) as u64;
            t = Edwards25519::select(&t, &self[j as usize], is_index);
        }
        let negate = (z & 1) as u64;
        Edwards25519::select(&t, &t.neg(), negate)
    }
}

impl Index<usize> for Window {
    type Output = Edwards25519;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl From<Edwards25519> for Window {
    fn from(value: Edwards25519) -> Self {
        let mut t = [Edwards25519::IDENTITY; 9];
        t[1] = value;
        t[2] = t[1].add(value);
        t[3] = t[2].add(value);
        t[4] = t[3].add(value);
        t[5] = t[4].add(value);
        t[6] = t[5].add(value);
        t[7] = t[6].add(value);
        t[8] = t[7].add(value);
        Self(t)
    }
}
