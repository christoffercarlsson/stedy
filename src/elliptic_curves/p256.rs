mod field;
mod scalar;

use crate::{
    elliptic_curves::weierstrass::Weierstrass,
    traits::{EcdsaCurve, EllipticCurve, WeierstrassScalar},
};
pub use {field::*, scalar::*};

pub struct P256;

type Point = Weierstrass<FieldP256, ScalarP256>;

impl EllipticCurve for P256 {
    const BASE_POINT: Self::Point = Point::BASE_POINT;

    type Point = Point;
    type Scalar = ScalarP256;
    type PointBytes = [u8; 33];
    type ScalarBytes = [u8; 32];
    type SharedSecretBytes = [u8; 32];

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
        ScalarP256::from_canonical(bytes)
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

impl EcdsaCurve for P256 {}
