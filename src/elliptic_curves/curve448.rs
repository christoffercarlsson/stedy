use crate::{
    Error,
    elliptic_curves::{MontgomeryLadder, MontgomeryScalar},
    traits::EllipticCurve,
};

#[cfg(feature = "hazmat")]
mod arithmetic;
mod edwards;
mod field;
mod scalar;

#[cfg(feature = "hazmat")]
pub use arithmetic::Field448With;
pub(crate) use edwards::Edwards448;
pub use {field::Field448, scalar::Scalar448};

pub struct Curve448;

impl Curve448 {
    pub(crate) const BITS: usize = 448;
    pub(crate) const COFACTOR: u8 = 4;
    pub(crate) const A24: u32 = 39081;
    pub(crate) const BASE_POINT: [u8; 56] = [
        5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
}

type Ladder = MontgomeryLadder<Field448>;

impl EllipticCurve for Curve448 {
    type Point = Field448;
    type Scalar = MontgomeryScalar<Field448>;
    type PointBytes = [u8; 56];
    type ScalarBytes = [u8; 56];
    type SharedSecretBytes = [u8; 56];

    fn point_from_bytes(bytes: &Self::PointBytes) -> Result<Self::Point, Error> {
        Ladder::point_from_bytes(bytes)
    }

    fn point_to_bytes(point: &Self::Point) -> Self::PointBytes {
        Ladder::point_to_bytes(point)
    }

    fn shared_secret_bytes(point: &Self::Point) -> Self::SharedSecretBytes {
        Ladder::shared_secret_bytes(point)
    }

    fn scalar_from_bytes(bytes: &Self::ScalarBytes) -> Result<Self::Scalar, Error> {
        Ladder::scalar_from_bytes(bytes)
    }

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes {
        Ladder::scalar_to_bytes(scalar)
    }

    fn scalar_mult_base(scalar: &Self::Scalar) -> Self::Point {
        Ladder::scalar_mult_base(scalar)
    }

    fn scalar_mult(scalar: &Self::Scalar, point: &Self::Point) -> Result<Self::Point, Error> {
        Ladder::scalar_mult(scalar, point)
    }
}
