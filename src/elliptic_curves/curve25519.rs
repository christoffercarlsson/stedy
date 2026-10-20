use crate::{
    Error,
    traits::{EdwardsScalar, EllipticCurve, FieldElement},
    utils::{Choice, Secret},
};

mod edwards;
mod field;
mod scalar;

pub use {edwards::Edwards25519, field::Field25519, scalar::Scalar25519};

pub struct Curve25519;

#[derive(Clone)]
pub struct Curve25519Scalar(Secret<[u8; 32]>);

impl Curve25519 {
    const BASE_POINT: Field25519 = Field25519::from_limbs([9, 0, 0, 0, 0]);
    const A24: u32 = 121665;
}

impl EllipticCurve for Curve25519 {
    type Point = Field25519;
    type Scalar = Curve25519Scalar;
    type PointBytes = [u8; 32];
    type ScalarBytes = [u8; 32];
    type SharedSecretBytes = [u8; 32];

    fn point_from_bytes(bytes: &Self::PointBytes) -> Result<Self::Point, Error> {
        Ok(Field25519::from(bytes))
    }

    fn point_to_bytes(point: &Self::Point) -> Self::PointBytes {
        point.into()
    }

    fn shared_secret_bytes(point: &Self::Point) -> Self::SharedSecretBytes {
        point.into()
    }

    fn scalar_from_bytes(bytes: &Self::ScalarBytes) -> Result<Self::Scalar, Error> {
        Ok(Curve25519Scalar(Secret::from(*bytes)))
    }

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes {
        *scalar.0.get()
    }

    fn scalar_mult_base(scalar: &Self::Scalar) -> Self::Point {
        Self::ladder(scalar, &Self::BASE_POINT)
    }

    fn scalar_mult(scalar: &Self::Scalar, point: &Self::Point) -> Result<Self::Point, Error> {
        let u = Self::ladder(scalar, point);
        if u.ct_eq(&Field25519::ZERO).to_bool() {
            Err(Error::InvalidKey)
        } else {
            Ok(u)
        }
    }
}

impl Curve25519 {
    pub(crate) fn mul_base(scalar: &[u8; 32]) -> [u8; 32] {
        let scalar = Curve25519Scalar(Secret::from(*scalar));
        Self::point_to_bytes(&Self::scalar_mult_base(&scalar))
    }

    fn ladder(scalar: &Curve25519Scalar, point: &Field25519) -> Field25519 {
        let mut scalar = scalar.0.clone();
        Scalar25519::clamp(scalar.get_mut());
        let x1 = *point;
        let mut x2 = Field25519::ONE;
        let mut z2 = Field25519::ZERO;
        let mut x3 = *point;
        let mut z3 = Field25519::ONE;
        let mut swap = Choice::FALSE;
        for i in (0..255).rev() {
            let byte_index = i / 8;
            let bit_index = i % 8;
            let bit = Choice::nonzero((scalar[byte_index] >> bit_index) & 1);
            swap ^= bit;
            Field25519::swap(&mut x2, &mut x3, swap);
            Field25519::swap(&mut z2, &mut z3, swap);
            swap = bit;
            let a = x2 + z2;
            let aa = a.square();
            let b = x2 - z2;
            let bb = b.square();
            let e = aa - bb;
            let c = x3 + z3;
            let d = x3 - z3;
            let da = d * a;
            let cb = c * b;
            x3 = (da + cb).square();
            z3 = x1 * (da - cb).square();
            x2 = aa * bb;
            z2 = e * (aa + e.mul_small(Self::A24));
        }
        Field25519::swap(&mut x2, &mut x3, swap);
        Field25519::swap(&mut z2, &mut z3, swap);
        x2 * z2.invert()
    }
}
