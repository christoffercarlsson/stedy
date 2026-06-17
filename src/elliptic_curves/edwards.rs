use {
    crate::traits::{EdwardsParams, EdwardsScalar, FieldElement},
    core::{
        array::from_fn,
        marker::PhantomData,
        ops::{Add, Index, Mul, Neg},
    },
};

pub(crate) struct Edwards<F, S>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    x: F,
    y: F,
    t: F,
    z: F,
    _marker: PhantomData<S>,
}

impl<F, S> Clone for Edwards<F, S>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<F, S> Copy for Edwards<F, S>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
}

impl<F, S> Edwards<F, S>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    pub(crate) const BASE_POINT: Self =
        Self::new(F::BASE_POINT_X, F::BASE_POINT_Y, F::BASE_POINT_T, F::ONE);
    const IDENTITY: Self = Self::new(F::ZERO, F::ONE, F::ZERO, F::ONE);

    const fn new(x: F, y: F, t: F, z: F) -> Self {
        Self {
            x,
            y,
            t,
            z,
            _marker: PhantomData::<S>,
        }
    }

    pub(crate) fn decompress(bytes: &F::Bytes) -> (Self, u64) {
        let slice = bytes.as_ref();
        let last = slice.len() - 1;
        let sign = (slice[last] >> 7) as u64;
        let mut bytes = *bytes;
        bytes[last] &= 127;
        let y = F::from(bytes);
        let y2 = y.square();
        let u = y2 - F::ONE;
        let v = F::D * y2 + F::ONE;
        let (mut x, mut valid) = u.sqrt(v);
        let is_zero = (x == F::ZERO) as u64;
        valid &= (is_zero & sign) ^ 1;
        let xs: F::Bytes = x.into();
        let negate = (xs[0] as u64 & 1) ^ sign;
        x = F::select(&x, &x.neg(), negate);
        let point = Self::new(x, y, x * y, F::ONE);
        (point, valid)
    }

    pub(crate) fn compress(&self) -> F::Bytes {
        let zi = self.z.invert();
        let x = self.x * zi;
        let y = self.y * zi;
        let xs: F::Bytes = x.into();
        let mut ys: F::Bytes = y.into();
        let sign = xs[0] & 1;
        let last = ys.as_ref().len() - 1;
        ys[last] &= 127;
        ys[last] |= sign << 7;
        ys
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
        let mut r = Projective::<F, S>::IDENTITY;
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

impl<F, S> PartialEq for Edwards<F, S>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    fn eq(&self, other: &Self) -> bool {
        (self.x * other.z) == (other.x * self.z)
    }
}

impl<F, S> Eq for Edwards<F, S>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
}

impl<F, S> Add for Edwards<F, S>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let a = (self.y - self.x) * (rhs.y - rhs.x);
        let b = (self.y + self.x) * (rhs.y + rhs.x);
        let c = self.t * F::D2 * rhs.t;
        let d = (self.z + self.z) * rhs.z;
        let e = b - a;
        let f = d - c;
        let g = d + c;
        let h = b + a;
        let x = e * f;
        let y = g * h;
        let t = e * h;
        let z = f * g;
        Self::new(x, y, t, z)
    }
}

impl<F, S> Mul<S> for Edwards<F, S>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    type Output = Self;

    fn mul(self, rhs: S) -> Self::Output {
        let window = Window::from(self);
        let digits = rhs.as_radix_16();
        let digits = digits.as_ref();
        let size = digits.len() - 1;
        let mut t2: Projective<F, S>;
        let mut t3 = Self::IDENTITY;
        let mut t1 = t3 + window.select(digits[size]);
        for i in (0..size).rev() {
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

impl<F, S> Add<ProjectiveNiels<F>> for Edwards<F, S>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    type Output = Completed<F, S>;

    fn add(self, rhs: ProjectiveNiels<F>) -> Self::Output {
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
        Completed::<F, S>::new(x, y, t, z)
    }
}

struct Projective<F, S>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    x: F,
    y: F,
    z: F,
    _marker: PhantomData<S>,
}

impl<F, S> Projective<F, S>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    const IDENTITY: Self = Self::new(F::ZERO, F::ONE, F::ONE);

    const fn new(x: F, y: F, z: F) -> Self {
        Self {
            x,
            y,
            z,
            _marker: PhantomData::<S>,
        }
    }

    fn double(self) -> Completed<F, S> {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square() + self.z.square();
        let d = self.x + self.y;
        let e = d.square();
        let y = a + b;
        let z = b - a;
        let x = e - y;
        let t = c - z;
        Completed::<F, S>::new(x, y, t, z)
    }

    fn to_extended(&self) -> Edwards<F, S> {
        Edwards::<F, S>::new(
            self.x * self.z,
            self.y * self.z,
            self.x * self.y,
            self.z.square(),
        )
    }
}

struct Completed<F, S>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    x: F,
    y: F,
    t: F,
    z: F,
    _marker: PhantomData<S>,
}

impl<F, S> Completed<F, S>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    const fn new(x: F, y: F, t: F, z: F) -> Self {
        Self {
            x,
            y,
            t,
            z,
            _marker: PhantomData::<S>,
        }
    }

    fn to_projective(&self) -> Projective<F, S> {
        Projective::<F, S>::new(self.x * self.t, self.y * self.z, self.z * self.t)
    }

    fn to_extended(&self) -> Edwards<F, S> {
        Edwards::<F, S>::new(
            self.x * self.t,
            self.y * self.z,
            self.x * self.y,
            self.z * self.t,
        )
    }
}

#[derive(Clone, Copy)]
struct ProjectiveNiels<F>
where
    F: FieldElement + EdwardsParams<F>,
{
    y_plus_x: F,
    y_minus_x: F,
    z: F,
    t2d: F,
}

impl<F> ProjectiveNiels<F>
where
    F: FieldElement + EdwardsParams<F>,
{
    const IDENTITY: Self = Self {
        y_plus_x: F::ONE,
        y_minus_x: F::ONE,
        z: F::ONE,
        t2d: F::ZERO,
    };

    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        Self {
            y_plus_x: F::select(&a.y_plus_x, &b.y_plus_x, condition),
            y_minus_x: F::select(&a.y_minus_x, &b.y_minus_x, condition),
            z: F::select(&a.z, &b.z, condition),
            t2d: F::select(&a.t2d, &b.t2d, condition),
        }
    }
}

impl<F: FieldElement + EdwardsParams<F>> Neg for ProjectiveNiels<F> {
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

impl<F, S> From<Edwards<F, S>> for ProjectiveNiels<F>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    fn from(point: Edwards<F, S>) -> Self {
        Self {
            y_plus_x: point.y + point.x,
            y_minus_x: point.y - point.x,
            z: point.z,
            t2d: point.t * F::D2,
        }
    }
}

struct Window<F>([ProjectiveNiels<F>; 8])
where
    F: FieldElement + EdwardsParams<F>;

impl<F> Window<F>
where
    F: FieldElement + EdwardsParams<F>,
{
    fn select(&self, x: i8) -> ProjectiveNiels<F> {
        let y = x as i16;
        let z = y >> 15;
        let i = ((y ^ z) - z) as u8;
        let mut t = ProjectiveNiels::<F>::IDENTITY;
        for j in 0..8 {
            let is_index = (((j + 1) ^ i) == 0) as u64;
            t = ProjectiveNiels::<F>::select(&t, &self[j as usize], is_index);
        }
        let negate = (z & 1) as u64;
        ProjectiveNiels::<F>::select(&t, &t.neg(), negate)
    }
}

impl<F: FieldElement + EdwardsParams<F>> Index<usize> for Window<F> {
    type Output = ProjectiveNiels<F>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<F, S> From<Edwards<F, S>> for Window<F>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    fn from(point: Edwards<F, S>) -> Self {
        let mut p = [Edwards::<F, S>::IDENTITY; 9];
        p[1] = point;
        p[2] = p[1] + point;
        p[3] = p[2] + point;
        p[4] = p[3] + point;
        p[5] = p[4] + point;
        p[6] = p[5] + point;
        p[7] = p[6] + point;
        p[8] = p[7] + point;
        let t: [ProjectiveNiels<F>; 8] = from_fn(|i| p[i + 1].into());
        Self(t)
    }
}

struct NafWindow<F>([ProjectiveNiels<F>; 8])
where
    F: FieldElement + EdwardsParams<F>;

impl<F, S> From<Edwards<F, S>> for NafWindow<F>
where
    F: FieldElement + EdwardsParams<F>,
    S: EdwardsScalar,
{
    fn from(point: Edwards<F, S>) -> Self {
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
            ProjectiveNiels::<F>::from(p1),
            ProjectiveNiels::<F>::from(p3),
            ProjectiveNiels::<F>::from(p5),
            ProjectiveNiels::<F>::from(p7),
            ProjectiveNiels::<F>::from(p9),
            ProjectiveNiels::<F>::from(p11),
            ProjectiveNiels::<F>::from(p13),
            ProjectiveNiels::<F>::from(p15),
        ])
    }
}

impl<F> NafWindow<F>
where
    F: FieldElement + EdwardsParams<F>,
{
    fn select(&self, x: i8) -> ProjectiveNiels<F> {
        if x == 0 {
            return ProjectiveNiels::<F>::IDENTITY;
        }
        let mut t = self.0[(x.unsigned_abs() >> 1) as usize];
        if x < 0 {
            t = t.neg();
        }
        t
    }
}
