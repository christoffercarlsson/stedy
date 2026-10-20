mod field;
mod scalar;
mod weierstrass;

use crate::{Error, elliptic_curves::weierstrass::Weierstrass, traits::EllipticCurve};
pub use {field::FieldP384, scalar::ScalarP384};

pub struct P384;

type Point = Weierstrass<FieldP384, ScalarP384>;

impl EllipticCurve for P384 {
    type Point = Point;
    type Scalar = ScalarP384;
    type PointBytes = [u8; 49];
    type ScalarBytes = [u8; 48];
    type SharedSecretBytes = [u8; 48];

    fn point_from_bytes(bytes: &Self::PointBytes) -> Result<Self::Point, Error> {
        Point::point_from_bytes(bytes)
    }

    fn point_to_bytes(point: &Self::Point) -> Self::PointBytes {
        Point::point_to_bytes(point)
    }

    fn shared_secret_bytes(point: &Self::Point) -> Self::SharedSecretBytes {
        Point::shared_secret_bytes(point)
    }

    fn scalar_from_bytes(bytes: &Self::ScalarBytes) -> Result<Self::Scalar, Error> {
        Point::scalar_from_bytes(bytes)
    }

    fn scalar_mult_base(scalar: &Self::Scalar) -> Self::Point {
        Point::scalar_mult_base(scalar)
    }

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes {
        Point::scalar_to_bytes(scalar)
    }

    fn scalar_mult(scalar: &Self::Scalar, point: &Self::Point) -> Result<Self::Point, Error> {
        Point::scalar_mult(scalar, point)
    }
}
