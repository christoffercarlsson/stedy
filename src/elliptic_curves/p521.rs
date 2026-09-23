mod field;
mod scalar;

use crate::{
    elliptic_curves::weierstrass::Weierstrass,
    traits::{EcdsaCurve, EllipticCurve, WeierstrassScalar},
};
pub use {field::*, scalar::*};

pub struct P521;

type Point = Weierstrass<FieldP521, ScalarP521>;

impl EllipticCurve for P521 {
    const BASE_POINT: Self::Point = Point::BASE_POINT;

    type Point = Point;
    type Scalar = ScalarP521;
    type PointBytes = [u8; 67];
    type ScalarBytes = [u8; 66];
    type SharedSecretBytes = [u8; 66];

    fn point_from_bytes(bytes: &Self::PointBytes) -> Option<Self::Point> {
        let (point, valid) = Point::decompress(bytes);
        if valid == 1 {
            Some(point)
        } else {
            None
        }
    }

    fn point_to_bytes(point: &Self::Point) -> Self::PointBytes {
        point.compress()
    }

    fn shared_secret_bytes(point: &Self::Point) -> Self::SharedSecretBytes {
        point.affine_x()
    }

    fn scalar_from_bytes(bytes: &Self::ScalarBytes) -> Option<Self::Scalar> {
        ScalarP521::from_canonical(bytes)
    }

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes {
        (*scalar).into()
    }

    fn scalar_mult(scalar: &Self::Scalar, point: &Self::Point) -> Option<Self::Point> {
        let result = point * scalar;
        if result.is_identity() {
            None
        } else {
            Some(result)
        }
    }
}

impl EcdsaCurve for P521 {}
