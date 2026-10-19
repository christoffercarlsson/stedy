use crate::{
    Error,
    traits::{EllipticCurve, FieldElement},
    utils::{Choice, Secret},
};

mod edwards;
mod field;
mod scalar;

pub use {edwards::Edwards448, field::Field448, scalar::Scalar448};

pub struct Curve448;

#[derive(Clone)]
pub struct Curve448Scalar(Secret<[u8; 56]>);

impl Curve448 {
    const BASE_POINT: Field448 = Field448::from_limbs([5, 0, 0, 0, 0, 0, 0, 0]);
    const A24: u32 = 39081;

    fn clamp(bytes: &mut [u8; 56]) {
        bytes[0] &= 252;
        bytes[55] |= 128;
    }
}

impl EllipticCurve for Curve448 {
    const BASE_POINT: Field448 = Self::BASE_POINT;

    type Point = Field448;
    type Scalar = Curve448Scalar;
    type PointBytes = [u8; 56];
    type ScalarBytes = [u8; 56];
    type SharedSecretBytes = [u8; 56];

    fn point_from_bytes(bytes: &Self::PointBytes) -> Result<Self::Point, Error> {
        Ok(Field448::from_le_bytes(bytes))
    }

    fn point_to_bytes(point: &Self::Point) -> Self::PointBytes {
        point.to_le_bytes()
    }

    fn shared_secret_bytes(point: &Self::Point) -> Self::SharedSecretBytes {
        point.to_le_bytes()
    }

    fn scalar_from_bytes(bytes: &Self::ScalarBytes) -> Result<Self::Scalar, Error> {
        Ok(Curve448Scalar(Secret::from(*bytes)))
    }

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes {
        *scalar.0.get()
    }

    fn scalar_mult_base(scalar: &Self::Scalar) -> Self::Point {
        Self::ladder(scalar, &Self::BASE_POINT)
    }

    fn scalar_mult(scalar: &Self::Scalar, point: &Self::Point) -> Result<Self::Point, Error> {
        let u = Self::ladder(scalar, point);
        if u.ct_eq(&Field448::ZERO).to_bool() {
            Err(Error::InvalidKey)
        } else {
            Ok(u)
        }
    }
}

impl Curve448 {
    fn ladder(scalar: &Curve448Scalar, point: &Field448) -> Field448 {
        let mut scalar = scalar.0.clone();
        Self::clamp(scalar.get_mut());
        let x1 = *point;
        let mut x2 = Field448::ONE;
        let mut z2 = Field448::ZERO;
        let mut x3 = *point;
        let mut z3 = Field448::ONE;
        let mut swap = Choice::FALSE;
        for i in (0..448).rev() {
            let byte_index = i / 8;
            let bit_index = i % 8;
            let bit = Choice::nonzero((scalar[byte_index] >> bit_index) & 1);
            swap ^= bit;
            Field448::swap(&mut x2, &mut x3, swap);
            Field448::swap(&mut z2, &mut z3, swap);
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
        Field448::swap(&mut x2, &mut x3, swap);
        Field448::swap(&mut z2, &mut z3, swap);
        x2 * z2.invert()
    }
}
