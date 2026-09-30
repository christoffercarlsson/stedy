use {
    crate::{
        traits::{ByteArray, FieldElement, WeierstrassParams, WeierstrassScalar},
        utils::Choice,
        Secret,
    },
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

    pub(crate) fn is_identity(&self) -> Choice {
        self.z.ct_eq(&F::ZERO)
    }

    pub(crate) fn compress(&self) -> F::PointBytes {
        let affine = Affine::<F>::from(*self);
        let xs: F::Bytes = affine.x.into();
        let mut bytes = F::PointBytes::new();
        bytes[0] = 2 | Self::is_odd(&affine.y);
        bytes[1..].copy_from_slice(xs.as_ref());
        bytes
    }

    pub(crate) fn affine_x(&self) -> F::Bytes {
        Affine::<F>::from(*self).x.into()
    }

    pub(crate) fn decompress(bytes: &F::PointBytes) -> (Self, Choice) {
        let prefix = bytes[0];
        let valid_prefix = Choice::eq(prefix, 2) | Choice::eq(prefix, 3);
        let sign = prefix & 1;
        let x = F::from(F::Bytes::from_slice(&bytes[1..]));
        let x2 = x.square();
        let x3 = x2 * x;
        let rhs = x3 + F::A * x + F::B;
        let (y, valid_sqrt) = rhs.sqrt(F::ONE);
        let negate = Choice::nonzero(Self::is_odd(&y) ^ sign);
        let y = F::select(&y, &y.neg(), negate);
        let point = Self::new(x, y, F::ONE);
        (point, valid_prefix & valid_sqrt)
    }

    pub(crate) fn mul_base(scalar: &S) -> Self {
        let bits = Secret::from(scalar.as_signed_bits());
        let bits = bits.get().as_ref();
        let columns = S::Bytes::SIZE;
        let low = &F::BASE_COMB_LOW;
        let high = &F::BASE_COMB_HIGH;
        let mut t = Self::IDENTITY + Self::comb_select(low, bits, columns, columns - 1);
        t = t + Self::comb_select(high, bits, columns, 5 * columns - 1);
        for i in (0..columns - 1).rev() {
            t = t.double();
            t = t + Self::comb_select(low, bits, columns, i);
            t = t + Self::comb_select(high, bits, columns, i + 4 * columns);
        }
        t
    }

    fn comb_select(table: &[[F; 2]; 8], bits: &[u8], columns: usize, i: usize) -> Affine<F> {
        let bit = |k: usize| (bits[k / 8] >> (k % 8)) & 1;
        let teeth = bit(i)
            | (bit(i + columns) << 1)
            | (bit(i + 2 * columns) << 2)
            | (bit(i + 3 * columns) << 3);
        let high = teeth >> 3;
        let index = (teeth ^ high.wrapping_sub(1)) & 7;
        let mut t = Affine::<F>::IDENTITY;
        for (j, entry) in table.iter().enumerate() {
            let is_index = Choice::eq(j, usize::from(index));
            t.x.assign(&entry[0], is_index);
            t.y.assign(&entry[1], is_index);
        }
        let negated = t.y.neg();
        t.y.assign(&negated, !Choice::nonzero(high));
        t
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
        let wb = NafWindow::<F>::base();
        let mut r = Jacobian::<F>::IDENTITY;
        loop {
            r = r.double();
            let da = na[i];
            let db = nb[i];
            if da != 0 {
                r = r.add_mixed(&wa.select(da));
            }
            if db != 0 {
                r = r.add_mixed(&wb.select(db));
            }
            if i == 0 {
                break;
            }
            i -= 1;
        }
        Self::new(r.x * r.z, r.y, r.z * r.z.square())
    }

    const fn new(x: F, y: F, z: F) -> Self {
        Self {
            x,
            y,
            z,
            _marker: PhantomData::<S>,
        }
    }

    fn double(&self) -> Self {
        let xx = self.x.square();
        let yy = self.y.square();
        let zz = self.z.square();
        let xy2 = (self.x * self.y).double_value();
        let xz2 = (self.x * self.z).double_value();
        let bzz = F::B * zz - xz2;
        let bzz3 = bzz + bzz + bzz;
        let yy_m_bzz3 = yy - bzz3;
        let yy_p_bzz3 = yy + bzz3;
        let y_frag = yy_p_bzz3 * yy_m_bzz3;
        let x_frag = yy_m_bzz3 * xy2;
        let zz3 = zz + zz + zz;
        let bxz2 = F::B * xz2 - (zz3 + xx);
        let bxz6 = bxz2 + bxz2 + bxz2;
        let xx3_m_zz3 = xx + xx + xx - zz3;
        let y = y_frag + xx3_m_zz3 * bxz6;
        let yz2 = (self.y * self.z).double_value();
        let x = x_frag - bxz6 * yz2;
        let z = yz2 * yy;
        let z = z + z;
        let z = z + z;
        Self::new(x, y, z)
    }

    fn mul(self, rhs: S) -> Self {
        let window = Window::from(self);
        let digits = Secret::from(rhs.as_radix_16());
        let digits = digits.get().as_ref();
        let mut r = Jacobian::<F>::IDENTITY;
        for &digit in digits.iter().rev() {
            r = r.double();
            r = r.double();
            r = r.double();
            r = r.double();
            let (point, is_identity) = window.select(digit);
            r = r.add_mixed_complete(&point, is_identity);
        }
        Self::new(r.x * r.z, r.y, r.z * r.z.square())
    }

    fn is_odd(f: &F) -> u8 {
        let bytes: F::Bytes = (*f).into();
        let lsb = bytes
            .as_ref()
            .last()
            .expect("Field element bytes are always non-empty");
        lsb & 1
    }
}

impl<F, S> Add for Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let xx = self.x * rhs.x;
        let yy = self.y * rhs.y;
        let zz = self.z * rhs.z;
        let xy_pairs = (self.x + self.y) * (rhs.x + rhs.y) - (xx + yy);
        let yz_pairs = (self.y + self.z) * (rhs.y + rhs.z) - (yy + zz);
        let xz_pairs = (self.x + self.z) * (rhs.x + rhs.z) - (xx + zz);
        let bzz = xz_pairs - F::B * zz;
        let bzz3 = bzz + bzz + bzz;
        let yy_m_bzz3 = yy - bzz3;
        let yy_p_bzz3 = yy + bzz3;
        let zz3 = zz + zz + zz;
        let bxz = F::B * xz_pairs - (zz3 + xx);
        let bxz3 = bxz + bxz + bxz;
        let xx3_m_zz3 = xx + xx + xx - zz3;
        Self::new(
            yy_p_bzz3 * xy_pairs - yz_pairs * bxz3,
            yy_p_bzz3 * yy_m_bzz3 + xx3_m_zz3 * bxz3,
            yy_m_bzz3 * yz_pairs + xy_pairs * xx3_m_zz3,
        )
    }
}

impl<F, S> Add<Affine<F>> for Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    type Output = Self;

    fn add(self, rhs: Affine<F>) -> Self::Output {
        let xx = self.x * rhs.x;
        let yy = self.y * rhs.y;
        let xy_pairs = (self.x + self.y) * (rhs.x + rhs.y) - (xx + yy);
        let yz_pairs = rhs.y * self.z + self.y;
        let xz_pairs = rhs.x * self.z + self.x;
        let bz = xz_pairs - F::B * self.z;
        let bz3 = bz + bz + bz;
        let yy_m_bz3 = yy - bz3;
        let yy_p_bz3 = yy + bz3;
        let z3 = self.z + self.z + self.z;
        let bxz = F::B * xz_pairs - (z3 + xx);
        let bxz3 = bxz + bxz + bxz;
        let xx3_m_z3 = xx + xx + xx - z3;
        Self::new(
            yy_p_bz3 * xy_pairs - yz_pairs * bxz3,
            yy_p_bz3 * yy_m_bz3 + xx3_m_z3 * bxz3,
            yy_m_bz3 * yz_pairs + xy_pairs * xx3_m_z3,
        )
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
        self.mul(rhs)
    }
}

impl<F, S> Mul<&S> for &Weierstrass<F, S>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    type Output = Weierstrass<F, S>;

    fn mul(self, rhs: &S) -> Self::Output {
        *self * rhs.clone()
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

    fn batch_from<S: WeierstrassScalar>(points: &[Weierstrass<F, S>; 8]) -> [Self; 8] {
        let mut prefix = [F::ONE; 8];
        let mut acc = F::ONE;
        for (i, point) in points.iter().enumerate() {
            prefix[i] = acc;
            let z = F::select(&point.z, &F::ONE, point.is_identity());
            acc *= z;
        }
        let mut inverse = acc.invert();
        let mut affine = [Self::IDENTITY; 8];
        for i in (0..8).rev() {
            let z = F::select(&points[i].z, &F::ONE, points[i].is_identity());
            let zi = inverse * prefix[i];
            inverse *= z;
            affine[i] = Self {
                x: points[i].x * zi,
                y: points[i].y * zi,
            };
        }
        affine
    }
}

#[derive(Clone, Copy)]
struct Jacobian<F>
where
    F: FieldElement + WeierstrassParams<F>,
{
    x: F,
    y: F,
    z: F,
}

impl<F> Jacobian<F>
where
    F: FieldElement + WeierstrassParams<F>,
{
    const IDENTITY: Self = Self {
        x: F::ONE,
        y: F::ONE,
        z: F::ZERO,
    };

    fn is_identity(&self) -> bool {
        self.z.ct_eq(&F::ZERO).to_bool()
    }

    fn assign(&mut self, other: &Self, condition: Choice) {
        self.x.assign(&other.x, condition);
        self.y.assign(&other.y, condition);
        self.z.assign(&other.z, condition);
    }

    fn add_mixed_complete(&self, rhs: &Affine<F>, rhs_is_identity: Choice) -> Self {
        let z1z1 = self.z.square();
        let u2 = rhs.x * z1z1;
        let s2 = rhs.y * self.z * z1z1;
        let h = u2 - self.x;
        let r = (s2 - self.y).double_value();
        let hh = h.square();
        let i = hh.double_value().double_value();
        let j = h * i;
        let v = self.x * i;
        let x = r.square() - j - v.double_value();
        let y = r * (v - x) - (self.y * j).double_value();
        let z = (self.z + h).square() - z1z1 - hh;
        let mut result = Self { x, y, z };
        let h_zero = h.ct_eq(&F::ZERO);
        let r_zero = r.ct_eq(&F::ZERO);
        result.assign(&self.double(), h_zero & r_zero);
        result.assign(&Self::IDENTITY, h_zero & !r_zero);
        let lifted = Self {
            x: rhs.x,
            y: rhs.y,
            z: F::ONE,
        };
        result.assign(&lifted, self.z.ct_eq(&F::ZERO));
        result.assign(self, rhs_is_identity);
        result
    }

    fn double(&self) -> Self {
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x * gamma;
        let alpha = (self.x - delta) * (self.x + delta);
        let alpha = alpha + alpha + alpha;
        let beta4 = beta.double_value().double_value();
        let x = alpha.square() - beta4.double_value();
        let z = (self.y + self.z).square() - gamma - delta;
        let gamma8 = gamma.square().double_value().double_value().double_value();
        let y = alpha * (beta4 - x) - gamma8;
        Self { x, y, z }
    }

    fn add_mixed(&self, rhs: &Affine<F>) -> Self {
        if self.is_identity() {
            return Self {
                x: rhs.x,
                y: rhs.y,
                z: F::ONE,
            };
        }
        let z1z1 = self.z.square();
        let u2 = rhs.x * z1z1;
        let s2 = rhs.y * self.z * z1z1;
        let h = u2 - self.x;
        let r = (s2 - self.y).double_value();
        if h.ct_eq(&F::ZERO).to_bool() {
            if r.ct_eq(&F::ZERO).to_bool() {
                return self.double();
            }
            return Self::IDENTITY;
        }
        let hh = h.square();
        let i = hh.double_value().double_value();
        let j = h * i;
        let v = self.x * i;
        let x = r.square() - j - v.double_value();
        let y = r * (v - x) - (self.y * j).double_value();
        let z = (self.z + h).square() - z1z1 - hh;
        Self { x, y, z }
    }
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
        let z = F::select(&point.z, &F::ONE, point.is_identity());
        let zi = z.invert();
        Self {
            x: point.x * zi,
            y: point.y * zi,
        }
    }
}

struct Window<F>([Affine<F>; 8])
where
    F: FieldElement + WeierstrassParams<F>;

impl<F> Window<F>
where
    F: FieldElement + WeierstrassParams<F>,
{
    fn select(&self, x: i8) -> (Affine<F>, Choice) {
        let xn = x as i16;
        let sign = xn >> 15;
        let idx = ((xn ^ sign) - sign) as u8;
        let mut t = Affine::<F>::IDENTITY;
        for j in 0u8..8 {
            let is_index = Choice::eq(j + 1, idx);
            t.x.assign(&self.0[j as usize].x, is_index);
            t.y.assign(&self.0[j as usize].y, is_index);
        }
        let negated = t.y.neg();
        t.y.assign(&negated, Choice::nonzero((sign & 1) as u8));
        (t, Choice::eq(idx, 0))
    }
}

impl<F, S> From<Weierstrass<F, S>> for Window<F>
where
    F: FieldElement + WeierstrassParams<F>,
    S: WeierstrassScalar,
{
    fn from(point: Weierstrass<F, S>) -> Self {
        let mut multiples = [point; 8];
        for i in 1..8 {
            multiples[i] = multiples[i - 1] + point;
        }
        Self(Affine::<F>::batch_from(&multiples))
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
        let p2 = point.double();
        let mut odd = [point; 8];
        for i in 1..8 {
            odd[i] = odd[i - 1] + p2;
        }
        Self(Affine::<F>::batch_from(&odd))
    }
}

impl<F> NafWindow<F>
where
    F: FieldElement + WeierstrassParams<F>,
{
    fn base() -> Self {
        Self(from_fn(|i| Affine {
            x: F::BASE_NAF[i][0],
            y: F::BASE_NAF[i][1],
        }))
    }

    fn select(&self, x: i8) -> Affine<F> {
        let mut t = self.0[(x.unsigned_abs() >> 1) as usize];
        if x < 0 {
            t = t.neg();
        }
        t
    }
}
