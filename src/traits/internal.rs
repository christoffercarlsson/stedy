use {
    crate::{
        Error,
        traits::{ByteArray, CryptoRng},
        utils::{Choice, Secret, is_zero, less_than},
    },
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    BigEndian,
    LittleEndian,
}

pub trait EdwardsParams<F: FieldElement> {
    const A: i8;
    const COFACTOR: u8;
    const D: F;
    const D2: F;
    const DOMAIN: &'static [u8];
    const DOMAIN_PURE: bool;
    const BASE_POINT_X: F;
    const BASE_POINT_Y: F;
    const BASE_POINT_T: F;
    const BASE_COMB_LOW: [[F; 3]; 8];
    const BASE_COMB_HIGH: [[F; 3]; 8];
}

pub trait EdwardsScalar:
    Sized
    + Clone
    + From<Self::Bytes>
    + From<Self::SecretBytes>
    + From<Self::WideBytes>
    + Into<Self::Bytes>
    + Add<Self, Output = Self>
    + AddAssign
    + Mul<Self, Output = Self>
    + MulAssign
    + Neg<Output = Self>
{
    type Bytes: ByteArray;
    type SecretBytes: ByteArray;
    type WideBytes: ByteArray;
    type Radix16: Copy + AsRef<[i8]>;
    type Naf5: AsRef<[i8]>;

    fn split(bytes: &Self::WideBytes) -> (Self::SecretBytes, Self::SecretBytes);

    fn clamp(bytes: &mut Self::SecretBytes);

    fn is_canonical(bytes: &Self::Bytes) -> Choice;

    fn as_radix_16(&self) -> Self::Radix16;

    fn non_adjacent_form_5(&self) -> Self::Naf5;

    fn as_signed_bits(&self) -> Self::SecretBytes;
}

pub trait EllipticCurve {
    type Point;
    type Scalar;
    type PointBytes: ByteArray;
    type ScalarBytes: ByteArray;
    type SharedSecretBytes: ByteArray;

    fn generate_scalar(rng: &mut impl CryptoRng) -> Result<Self::Scalar, Error> {
        loop {
            let mut bytes = Secret::from(Self::ScalarBytes::new());
            rng.fill(bytes.get_mut().as_mut())?;
            if let Ok(scalar) = Self::scalar_from_bytes(bytes.get()) {
                return Ok(scalar);
            }
        }
    }

    fn scalar_mult_base(scalar: &Self::Scalar) -> Self::Point;

    fn point_from_bytes(bytes: &Self::PointBytes) -> Result<Self::Point, Error>;

    fn point_to_bytes(point: &Self::Point) -> Self::PointBytes;

    fn shared_secret_bytes(point: &Self::Point) -> Self::SharedSecretBytes;

    fn scalar_from_bytes(bytes: &Self::ScalarBytes) -> Result<Self::Scalar, Error>;

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes;

    fn scalar_mult(scalar: &Self::Scalar, point: &Self::Point) -> Result<Self::Point, Error>;
}

pub trait FieldElement:
    Sized
    + Copy
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + MulAssign
    + Neg<Output = Self>
    + From<Self::Bytes>
    + Into<Self::Bytes>
{
    const CAPACITY: usize;
    const BYTE_ORDER: ByteOrder;

    const ZERO: Self;
    const ONE: Self;

    type Bytes: ByteArray;

    fn swap(a: &mut Self, b: &mut Self, condition: Choice) {
        let swapped = Self::select(a, b, condition);
        *b = Self::select(b, a, condition);
        *a = swapped;
    }

    fn select(a: &Self, b: &Self, condition: Choice) -> Self;

    fn assign(&mut self, other: &Self, condition: Choice) {
        *self = Self::select(self, other, condition);
    }

    fn ct_eq(&self, other: &Self) -> Choice {
        let difference: Self::Bytes = (*self - *other).into();
        is_zero(difference.as_ref())
    }

    fn square(self) -> Self {
        self * self
    }

    fn square2(self) -> Self {
        let square = self.square();
        square + square
    }

    fn double_value(self) -> Self {
        self + self
    }

    fn invert(self) -> Self;

    fn sqrt(self, b: Self) -> (Self, Choice);

    fn from_u32(value: u32) -> Self {
        let mut bytes = Self::Bytes::new();
        let size = Self::Bytes::SIZE.min(4);
        match Self::BYTE_ORDER {
            ByteOrder::BigEndian => bytes.as_mut()[Self::Bytes::SIZE - size..]
                .copy_from_slice(&value.to_be_bytes()[4 - size..]),
            ByteOrder::LittleEndian => {
                bytes.as_mut()[..size].copy_from_slice(&value.to_le_bytes()[..size])
            }
        }
        Self::from(bytes)
    }
}

pub trait MlKemParams<const K: usize> {
    const ETA1: usize;
    const ETA2: usize;
    const DU: usize;
    const DV: usize;

    type Seed: ByteArray;
    type SharedSecret: ByteArray;
    type PrivateKey: ByteArray;
    type PublicKey: ByteArray;
    type Ciphertext: ByteArray;
}

pub trait MlDsaParams<const K: usize, const L: usize> {
    const TAU: usize;
    const LAMBDA: usize;
    const GAMMA1: i32;
    const GAMMA2: i32;
    const ETA: i32;
    const BETA: i32;
    const OMEGA: usize;

    type Seed: ByteArray;
    type PrivateKey: ByteArray;
    type PublicKey: ByteArray;
    type Signature: ByteArray;
}

pub trait MontgomeryFormParams<const LIMBS: usize>: Copy + Clone {
    const MOD: [u64; LIMBS];
    const ONE: [u64; LIMBS];
    const R2: [u64; LIMBS];
    const N0: u64;
}

pub trait MontgomeryParams<F: FieldElement> {
    const BITS: usize;
    const COFACTOR: u8;
    const BASE_POINT: F;

    type PointBytes: ByteArray;

    fn point_from_bytes(bytes: &Self::PointBytes) -> F;

    fn point_to_bytes(point: &F) -> Self::PointBytes;

    fn mul_a24(element: F) -> F;
}

pub trait WeierstrassParams<F: FieldElement> {
    const A: F;
    const B: F;
    const BASE_POINT_X: F;
    const BASE_POINT_Y: F;
    const BASE_NAF: [[F; 2]; 8];
    const BASE_COMB_LOW: [[F; 2]; 8];
    const BASE_COMB_HIGH: [[F; 2]; 8];

    type PointBytes: ByteArray;
}

pub trait WeierstrassScalar:
    Sized
    + Clone
    + From<Self::Bytes>
    + Into<Self::Bytes>
    + Add<Self, Output = Self>
    + AddAssign
    + Sub<Self, Output = Self>
    + SubAssign
    + Mul<Self, Output = Self>
    + MulAssign
    + Neg<Output = Self>
{
    const ORDER_BITS: usize;
    const ORDER: Self::Bytes;

    type Bytes: ByteArray;
    type Radix16: Copy + AsRef<[i8]>;
    type Naf5: AsRef<[i8]>;

    fn is_zero(&self) -> Choice;

    fn ct_eq(&self, other: &Self) -> Choice;

    fn invert(self) -> Self;

    fn from_canonical(bytes: &Self::Bytes) -> Option<Self> {
        let non_zero = !is_zero(bytes.as_ref());
        let below = less_than(bytes.as_ref(), Self::ORDER.as_ref());
        (non_zero & below).to_bool().then(|| Self::from(*bytes))
    }

    fn as_radix_16(&self) -> Self::Radix16;

    fn non_adjacent_form_5(&self) -> Self::Naf5;

    fn as_signed_bits(&self) -> Self::Bytes;
}

pub(crate) trait Sealed {}

impl<const N: usize> Sealed for [u8; N] {}
