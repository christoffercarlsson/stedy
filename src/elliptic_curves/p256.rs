#[cfg(feature = "hazmat")]
mod arithmetic;
mod field;
mod scalar;
mod weierstrass;

use crate::{Error, elliptic_curves::weierstrass::Weierstrass, traits::EllipticCurve};
#[cfg(feature = "hazmat")]
pub use arithmetic::FieldP256With;
pub use field::FieldP256;
pub(crate) use scalar::ScalarP256;

pub struct P256;

type Point = Weierstrass<FieldP256, ScalarP256>;

impl EllipticCurve for P256 {
    type Point = Point;
    type Scalar = ScalarP256;
    type PointBytes = [u8; 33];
    type ScalarBytes = [u8; 32];
    type SharedSecretBytes = [u8; 32];

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
