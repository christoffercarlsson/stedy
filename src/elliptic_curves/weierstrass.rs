use {
    crate::traits::{ByteArray, FieldElement, WeierstrassParams, WeierstrassScalar},
    core::{
        array::from_fn,
        marker::PhantomData,
        ops::{Add, Mul, Neg},
    },
};

pub struct Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    x: F,
    y: F,
    z: F,
    _marker: PhantomData<S>,
}

impl<F, S> Clone for Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<F, S> Copy for Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
}

impl<F, S> Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    pub(crate) const BASE_POINT: Self = Self::new(F::BASE_POINT_X, F::BASE_POINT_Y, F::ONE);
    const IDENTITY: Self = Self::new(F::ZERO, F::ONE, F::ZERO);

    pub(crate) fn is_identity(&self) -> bool {
        self.z == F::ZERO
    }

    pub(crate) fn compress(&self) -> F::PointBytes {
        let affine = Affine::<F>::from(*self);
        let xs: F::Bytes = affine.x.into();
        let mut bytes = F::PointBytes::new();
        bytes[0] = 2 | Self::is_odd(&affine.y) as u8;
        bytes[1..].copy_from_slice(xs.as_ref());
        bytes
    }

    pub(crate) fn affine_x(&self) -> F::Bytes {
        Affine::<F>::from(*self).x.into()
    }

    pub(crate) fn decompress(bytes: &F::PointBytes) -> (Self, u64) {
        let prefix = bytes[0];
        let valid_prefix = ((prefix == 2) | (prefix == 3)) as u64;
        let sign = (prefix & 1) as u64;
        let x = F::from(*F::Bytes::from_slice(&bytes[1..]));
        let x2 = x.square();
        let x3 = x2 * x;
        let rhs = x3 + F::A * x + F::B;
        let (y, valid_sqrt) = rhs.sqrt(F::ONE);
        let negate = Self::is_odd(&y) ^ sign;
        let y = F::select(&y, &y.neg(), negate);
        let point = Self::new(x, y, F::ONE);
        (point, valid_prefix & valid_sqrt)
    }

    #[allow(non_snake_case)]
    pub(crate) fn vartime_double_base(a: &S, A: Self, b: &S) -> Self {
        let na = a.non_adjacent_form_5();
        let nb = b.non_adjacent_form_5();
        let na = na.as_ref();
        let nb = nb.as_ref();
        let naf_size = na.len();
        let mut i: usize = naf_size - 1;
        for j in (0..naf_size).rev() {
            i = j;
            if na[i] != 0 || nb[i] != 0 {
                break;
            }
        }
        let wa = NafWindow::from(A);
        let wb = NafWindow::from(Self::BASE_POINT);
        let mut r = Self::IDENTITY;
        loop {
            r = r.double();
            let da = na[i];
            let db = nb[i];
            if da != 0 {
                r = r + wa.select(da);
            }
            if db != 0 {
                r = r + wb.select(db);
            }
            if i == 0 {
                break;
            }
            i -= 1;
        }
        r
    }

    const fn new(x: F, y: F, z: F) -> Self {
        Self {
            x,
            y,
            z,
            _marker: PhantomData::<S>,
        }
    }

    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        Self::new(
            F::select(&a.x, &b.x, condition),
            F::select(&a.y, &b.y, condition),
            F::select(&a.z, &b.z, condition),
        )
    }

    fn double(&self) -> Self {
        let two = F::from(2);
        let three = F::from(3);
        let eight = F::from(8);
        let xx = self.x.square();
        let yy = self.y.square();
        let yyyy = yy.square();
        let zz = self.z.square();
        let s = two * ((self.x + yy).square() - xx - yyyy);
        let m = three * xx + F::A * zz.square();
        let t = m.square() - two * s;
        let x3 = t;
        let y3 = m * (s - t) - eight * yyyy;
        let z3 = (self.y + self.z).square() - yy - zz;
        Self::new(x3, y3, z3)
    }

    fn is_odd(f: &F) -> u64 {
        let bytes: F::Bytes = (*f).into();
        let lsb = bytes
            .as_ref()
            .last()
            .expect("Field element bytes are always non-empty");
        (lsb & 1) as u64
    }
}

impl<F, S> PartialEq for Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    fn eq(&self, other: &Self) -> bool {
        let is_identity = self.is_identity() as u64 & other.is_identity() as u64;
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let x1 = self.x * z2z2;
        let x2 = other.x * z1z1;
        let y1 = self.y * other.z * z2z2;
        let y2 = other.y * self.z * z1z1;
        let is_equal = (x1 == x2) as u64 & (y1 == y2) as u64;
        (is_identity | is_equal) == 1
    }
}

impl<F, S> Eq for Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
}

impl<F, S> Add for Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let two = F::from(2);
        let z1z1 = self.z.square();
        let z2z2 = rhs.z.square();
        let u1 = self.x * z2z2;
        let u2 = rhs.x * z1z1;
        let s1 = self.y * rhs.z * z2z2;
        let s2 = rhs.y * self.z * z1z1;
        let h = u2 - u1;
        let i = (two * h).square();
        let j = h * i;
        let r = two * (s2 - s1);
        let v = u1 * i;
        let x3 = r.square() - j - two * v;
        let y3 = r * (v - x3) - two * s1 * j;
        let z3 = ((self.z + rhs.z).square() - z1z1 - z2z2) * h;
        let sum = Self::new(x3, y3, z3);
        let coincident = (h == F::ZERO) as u64 & (s1 == s2) as u64;
        let result = Self::select(&sum, &self.double(), coincident);
        let result = Self::select(&result, &rhs, self.is_identity() as u64);
        Self::select(&result, &self, rhs.is_identity() as u64)
    }
}

impl<F, S> Add<Affine<F>> for Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    type Output = Self;

    fn add(self, rhs: Affine<F>) -> Self::Output {
        let two = F::from(2);
        let four = F::from(4);
        let z1z1 = self.z.square();
        let u2 = rhs.x * z1z1;
        let s2 = rhs.y * self.z * z1z1;
        let h = u2 - self.x;
        let hh = h.square();
        let i = four * hh;
        let j = h * i;
        let r = two * (s2 - self.y);
        let v = self.x * i;
        let x3 = r.square() - j - two * v;
        let y3 = r * (v - x3) - two * self.y * j;
        let z3 = (self.z + h).square() - z1z1 - hh;
        let sum = Self::new(x3, y3, z3);
        let lifted = Self::new(rhs.x, rhs.y, F::ONE);
        Self::select(&sum, &lifted, self.is_identity() as u64)
    }
}

impl<F, S> Neg for Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::new(self.x, self.y.neg(), self.z)
    }
}

impl<F, S> Mul<S> for Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    type Output = Self;

    fn mul(self, rhs: S) -> Self::Output {
        let window = Window::from(self);
        let digits = rhs.as_radix_16();
        let digits = digits.as_ref();
        let mut r = Self::IDENTITY;
        for &digit in digits.iter().rev() {
            r = r.double();
            r = r.double();
            r = r.double();
            r = r.double();
            r = r + window.select(digit);
        }
        r
    }
}

impl<F, S> Mul<&S> for &Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    type Output = Weierstrass<F, S>;

    fn mul(self, rhs: &S) -> Self::Output {
        *self * *rhs
    }
}

#[derive(Clone, Copy)]
struct Affine<F>
where
    F: FieldElement + WeierstrassParams<F>,
{
    x: F,
    y: F,
}

impl<F> Affine<F>
where
    F: FieldElement + WeierstrassParams<F>,
{
    const IDENTITY: Self = Self {
        x: F::ZERO,
        y: F::ZERO,
    };
}

impl<F> Neg for Affine<F>
where
    F: FieldElement + WeierstrassParams<F>,
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            x: self.x,
            y: self.y.neg(),
        }
    }
}

impl<F, S> From<Weierstrass<F, S>> for Affine<F>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    fn from(point: Weierstrass<F, S>) -> Self {
        let z = F::select(&point.z, &F::ONE, point.is_identity() as u64);
        let zi = z.invert();
        let zi2 = zi.square();
        let zi3 = zi2 * zi;
        Self {
            x: point.x * zi2,
            y: point.y * zi3,
        }
    }
}

struct Window<F, S>([Weierstrass<F, S>; 8])
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar;

impl<F, S> Window<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    fn select(&self, x: i8) -> Weierstrass<F, S> {
        let xn = x as i16;
        let sign = xn >> 15;
        let idx = ((xn ^ sign) - sign) as u8;
        let mut t = Weierstrass::<F, S>::IDENTITY;
        for j in 0u8..8 {
            let is_index = (((j + 1) ^ idx) == 0) as u64;
            t = Weierstrass::<F, S>::select(&t, &self.0[j as usize], is_index);
        }
        let negate = (sign & 1) as u64;
        Weierstrass::<F, S>::select(&t, &t.neg(), negate)
    }
}

impl<F, S> From<Weierstrass<F, S>> for Window<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    fn from(point: Weierstrass<F, S>) -> Self {
        let mut p = [Weierstrass::<F, S>::IDENTITY; 9];
        p[1] = point;
        p[2] = p[1].double();
        p[3] = p[2] + point;
        p[4] = p[3] + point;
        p[5] = p[4] + point;
        p[6] = p[5] + point;
        p[7] = p[6] + point;
        p[8] = p[7] + point;
        Self(from_fn(|i| p[i + 1]))
    }
}

struct NafWindow<F>([Affine<F>; 8])
where
    F: FieldElement + WeierstrassParams<F>;

impl<F, S> From<Weierstrass<F, S>> for NafWindow<F>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    fn from(point: Weierstrass<F, S>) -> Self {
        let p1 = point;
        let p2 = p1.double();
        let p3 = p1 + p2;
        let p5 = p3 + p2;
        let p7 = p5 + p2;
        let p9 = p7 + p2;
        let p11 = p9 + p2;
        let p13 = p11 + p2;
        let p15 = p13 + p2;
        Self([
            Affine::<F>::from(p1),
            Affine::<F>::from(p3),
            Affine::<F>::from(p5),
            Affine::<F>::from(p7),
            Affine::<F>::from(p9),
            Affine::<F>::from(p11),
            Affine::<F>::from(p13),
            Affine::<F>::from(p15),
        ])
    }
}

impl<F> NafWindow<F>
where
    F: FieldElement + WeierstrassParams<F>,
{
    fn select(&self, x: i8) -> Affine<F> {
        if x == 0 {
            return Affine::<F>::IDENTITY;
        }
        let mut t = self.0[(x.unsigned_abs() >> 1) as usize];
        if x < 0 {
            t = t.neg();
        }
        t
    }
}
