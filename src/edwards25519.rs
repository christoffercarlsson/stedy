use {
    crate::{
        curve25519::Curve25519,
        scalar25519::Scalar25519,
        traits::{EdwardsPoint, FieldElement},
    },
    core::{
        array::from_fn,
        ops::{Add, Index, Mul, Neg},
    },
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
        x: Curve25519::from_51bit([
            1738742601995546,
            1146398526822698,
            2070867633025821,
            562264141797630,
            587772402128613,
        ]),
        y: Curve25519::from_51bit([
            1801439850948184,
            1351079888211148,
            450359962737049,
            900719925474099,
            1801439850948198,
        ]),
        z: Curve25519::ONE,
        t: Curve25519::from_51bit([
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

    fn vartime_double_base(a: &Scalar25519, p: Self, b: &Scalar25519) -> Self {
        let na = a.non_adjacent_form_5();
        let nb = b.non_adjacent_form_5();
        let mut i: usize = 255;
        for j in (0..256).rev() {
            i = j;
            if na[i] != 0 || nb[i] != 0 {
                break;
            }
        }
        let wa = NafWindow::from(p);
        let wb = NafWindow::from(Self::BASE_POINT);
        let mut r = Projective25519::IDENTITY;
        loop {
            let mut t = r.double();
            let da = na[i];
            let db = nb[i];
            if da != 0 {
                t = t.to_extended() + wa.select(da);
            }
            if db != 0 {
                t = t.to_extended() + wb.select(db);
            }
            r = t.to_projective();
            if i == 0 {
                break;
            }
            i -= 1;
        }
        r.to_extended()
    }
}

impl Edwards25519 {
    const D: Curve25519 = Curve25519::from_51bit([
        929955233495203,
        466365720129213,
        1662059464998953,
        2033849074728123,
        1442794654840575,
    ]);
    const D2: Curve25519 = Curve25519::from_51bit([
        1859910466990425,
        932731440258426,
        1072319116312658,
        1815898335770999,
        633789495995903,
    ]);
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
        let mut t2: Projective25519;
        let mut t3 = Self::IDENTITY;
        let mut t1 = t3 + window.select(digits[63]);
        for i in (0..63).rev() {
            t2 = t1.to_projective();
            t1 = t2.double();
            t2 = t1.to_projective();
            t1 = t2.double();
            t2 = t1.to_projective();
            t1 = t2.double();
            t2 = t1.to_projective();
            t1 = t2.double();
            t3 = t1.to_extended();
            t1 = t3 + window.select(digits[i]);
        }
        t1.to_extended()
    }
}

impl Add<ProjectiveNiels25519> for Edwards25519 {
    type Output = Completed25519;

    fn add(self, rhs: ProjectiveNiels25519) -> Self::Output {
        let a = self.y + self.x;
        let b = self.y - self.x;
        let c = a * rhs.y_plus_x;
        let d = b * rhs.y_minus_x;
        let e = self.t * rhs.t2d;
        let f = self.z * rhs.z;
        let g = f + f;
        let x = c - d;
        let y = c + d;
        let t = g - e;
        let z = g + e;
        Completed25519 { x, y, t, z }
    }
}

struct Projective25519 {
    x: Curve25519,
    y: Curve25519,
    z: Curve25519,
}

impl Projective25519 {
    const IDENTITY: Self = Self {
        x: Curve25519::ZERO,
        y: Curve25519::ONE,
        z: Curve25519::ONE,
    };

    fn double(self) -> Completed25519 {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square() + self.z.square();
        let d = self.x + self.y;
        let e = d.square();
        let y = a + b;
        let z = b - a;
        let x = e - y;
        let t = c - z;
        Completed25519 { x, y, t, z }
    }

    fn to_extended(self) -> Edwards25519 {
        Edwards25519 {
            x: self.x * self.z,
            y: self.y * self.z,
            t: self.x * self.y,
            z: self.z.square(),
        }
    }
}

struct Completed25519 {
    x: Curve25519,
    y: Curve25519,
    t: Curve25519,
    z: Curve25519,
}

impl Completed25519 {
    fn to_projective(self) -> Projective25519 {
        Projective25519 {
            x: self.x * self.t,
            y: self.y * self.z,
            z: self.z * self.t,
        }
    }

    fn to_extended(self) -> Edwards25519 {
        Edwards25519 {
            x: self.x * self.t,
            y: self.y * self.z,
            z: self.z * self.t,
            t: self.x * self.y,
        }
    }
}

#[derive(Clone, Copy)]
struct ProjectiveNiels25519 {
    y_plus_x: Curve25519,
    y_minus_x: Curve25519,
    z: Curve25519,
    t2d: Curve25519,
}

impl ProjectiveNiels25519 {
    const IDENTITY: Self = Self {
        y_plus_x: Curve25519::ONE,
        y_minus_x: Curve25519::ONE,
        z: Curve25519::ONE,
        t2d: Curve25519::ZERO,
    };

    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        Self {
            y_plus_x: Curve25519::select(&a.y_plus_x, &b.y_plus_x, condition),
            y_minus_x: Curve25519::select(&a.y_minus_x, &b.y_minus_x, condition),
            z: Curve25519::select(&a.z, &b.z, condition),
            t2d: Curve25519::select(&a.t2d, &b.t2d, condition),
        }
    }
}

impl Neg for ProjectiveNiels25519 {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            y_plus_x: self.y_minus_x,
            y_minus_x: self.y_plus_x,
            z: self.z,
            t2d: self.t2d.neg(),
        }
    }
}

impl From<Edwards25519> for ProjectiveNiels25519 {
    fn from(point: Edwards25519) -> Self {
        Self {
            y_plus_x: point.y + point.x,
            y_minus_x: point.y - point.x,
            z: point.z,
            t2d: point.t * Edwards25519::D2,
        }
    }
}

struct Window([ProjectiveNiels25519; 8]);

impl Window {
    fn select(&self, x: i8) -> ProjectiveNiels25519 {
        let y = x as i16;
        let z = y >> 15;
        let i = ((y ^ z) - z) as u8;
        let mut t = ProjectiveNiels25519::IDENTITY;
        for j in 0..8 {
            let is_index = (((j + 1) ^ i) == 0) as u64;
            t = ProjectiveNiels25519::select(&t, &self[j as usize], is_index);
        }
        let negate = (z & 1) as u64;
        ProjectiveNiels25519::select(&t, &t.neg(), negate)
    }
}

impl Index<usize> for Window {
    type Output = ProjectiveNiels25519;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl From<Edwards25519> for Window {
    fn from(point: Edwards25519) -> Self {
        let mut p = [Edwards25519::IDENTITY; 9];
        p[1] = point;
        p[2] = p[1].add(point);
        p[3] = p[2].add(point);
        p[4] = p[3].add(point);
        p[5] = p[4].add(point);
        p[6] = p[5].add(point);
        p[7] = p[6].add(point);
        p[8] = p[7].add(point);
        let t: [ProjectiveNiels25519; 8] = from_fn(|i| p[i + 1].into());
        Self(t)
    }
}

struct NafWindow([ProjectiveNiels25519; 8]);

impl From<Edwards25519> for NafWindow {
    fn from(point: Edwards25519) -> Self {
        let p1 = point;
        let p2 = p1 + p1;
        let p3 = p1 + p2;
        let p5 = p3 + p2;
        let p7 = p5 + p2;
        let p9 = p7 + p2;
        let p11 = p9 + p2;
        let p13 = p11 + p2;
        let p15 = p13 + p2;
        Self([
            ProjectiveNiels25519::from(p1),
            ProjectiveNiels25519::from(p3),
            ProjectiveNiels25519::from(p5),
            ProjectiveNiels25519::from(p7),
            ProjectiveNiels25519::from(p9),
            ProjectiveNiels25519::from(p11),
            ProjectiveNiels25519::from(p13),
            ProjectiveNiels25519::from(p15),
        ])
    }
}

impl NafWindow {
    fn select(&self, x: i8) -> ProjectiveNiels25519 {
        if x == 0 {
            return ProjectiveNiels25519::IDENTITY;
        }
        let mut t = self.0[(x.unsigned_abs() >> 1) as usize];
        if x < 0 {
            t = t.neg();
        }
        t
    }
}
