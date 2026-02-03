use crate::traits::{EdwardsScalar, EllipticCurve, FieldElement};

mod field;
mod scalar;

pub use {field::Field25519, scalar::Scalar25519};

pub struct Curve25519;

impl Curve25519 {
    const BASE_POINT: Field25519 = Field25519::from_limbs([9, 0, 0, 0, 0]);
    const A24: Field25519 = Field25519::from_limbs([121665, 0, 0, 0, 0]);
}

impl EllipticCurve for Curve25519 {
    const BASE_POINT: Field25519 = Self::BASE_POINT;

    type Point = Field25519;
    type Scalar = [u8; 32];
    type PointBytes = [u8; 32];
    type ScalarBytes = [u8; 32];

    fn point_from_bytes(bytes: &Self::PointBytes) -> Option<Self::Point> {
        Some(Field25519::from(bytes))
    }

    fn point_to_bytes(point: &Self::Point) -> Self::PointBytes {
        point.into()
    }

    fn scalar_from_bytes(bytes: &Self::ScalarBytes) -> Option<Self::Scalar> {
        Some(*bytes)
    }

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes {
        *scalar
    }

    fn scalar_mult(scalar: &Self::Scalar, point: &Self::Point) -> Option<Self::Point> {
        let mut scalar = *scalar;
        Scalar25519::clamp(&mut scalar);
        let x1 = *point;
        let mut x2 = Field25519::ONE;
        let mut z2 = Field25519::ZERO;
        let mut x3 = *point;
        let mut z3 = Field25519::ONE;
        let mut swap = 0;
        for i in (0..255).rev() {
            let byte_index = i / 8;
            let bit_index = i % 8;
            let bit = ((scalar[byte_index] >> bit_index) & 1) as u64;
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
            z2 = e * (aa + Self::A24 * e);
        }
        Field25519::swap(&mut x2, &mut x3, swap);
        Field25519::swap(&mut z2, &mut z3, swap);
        Some(x2 / z2)
    }
}
