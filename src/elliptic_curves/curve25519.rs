use crate::{
    Error,
    elliptic_curves::{MontgomeryLadder, MontgomeryScalar},
    traits::EllipticCurve,
};

mod edwards;
mod field;
mod scalar;

pub use {edwards::Edwards25519, field::Field25519, scalar::Scalar25519};

pub struct Curve25519;

impl Curve25519 {
    pub const BITS: usize = 255;
    pub const COFACTOR: u8 = 8;
    pub const A24: u32 = 121665;
    pub const BASE_POINT: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
}

type Ladder = MontgomeryLadder<Field25519>;

impl EllipticCurve for Curve25519 {
    type Point = Field25519;
    type Scalar = MontgomeryScalar<Field25519>;
    type PointBytes = [u8; 32];
    type ScalarBytes = [u8; 32];
    type SharedSecretBytes = [u8; 32];

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

impl Curve25519 {
    pub(crate) fn mul_base(scalar: &[u8; 32]) -> [u8; 32] {
        Ladder::mul_base(scalar)
    }
}
