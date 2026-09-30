#![allow(dead_code)]
use {
    crate::utils::{is_zero, less_than, Choice, Secret},
    core::ops::{
        Add, AddAssign, Div, DivAssign, Index, IndexMut, Mul, MulAssign, Neg, RangeFrom, Sub,
        SubAssign,
    },
};

pub trait Authenticator<C: SeekableStreamCipher> {
    const ACCEPTS_AAD: bool = true;

    type Output;

    fn new(cipher: &mut C) -> Self;

    fn tag(self, ciphertext: &[u8], aad: Option<&[u8]>) -> Self::Output;

    fn verify(self, ciphertext: &[u8], aad: Option<&[u8]>, tag: &Self::Output) -> bool;
}

#[allow(private_bounds)]
pub trait ByteArray:
    Copy
    + Sized
    + AsRef<[u8]>
    + AsMut<[u8]>
    + Index<usize, Output = u8>
    + Index<RangeFrom<usize>, Output = [u8]>
    + IndexMut<usize, Output = u8>
    + IndexMut<RangeFrom<usize>, Output = [u8]>
    + Sealed
{
    const SIZE: usize;

    fn new() -> Self;

    fn from_slice(slice: &[u8]) -> Self;

    fn from_slice_checked(slice: &[u8]) -> Option<Self>;
}

pub trait CryptoRng {
    fn fill(&mut self, bytes: &mut [u8]);

    fn next_u32(&mut self) -> u32;

    fn next_u64(&mut self) -> u64;
}

pub trait Digest {
    const OUTPUT_SIZE: usize;

    type Output: ByteArray;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> Self::Output;

    fn finalize_into(self, output: &mut [u8]);
}

pub trait EdwardsParams<F: FieldElement> {
    const D: F;
    const D2: F;
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
    const BASE_POINT: Self::Point;

    type Point;
    type Scalar;
    type PointBytes: ByteArray;
    type ScalarBytes: ByteArray;
    type SharedSecretBytes: ByteArray;

    fn generate_scalar(rng: &mut impl CryptoRng) -> Self::Scalar {
        loop {
            let mut bytes = Secret::<Self::ScalarBytes>::new();
            rng.fill(bytes.get_mut().as_mut());
            if let Some(scalar) = Self::scalar_from_bytes(bytes.get()) {
                return scalar;
            }
        }
    }

    fn scalar_mult_base(scalar: &Self::Scalar) -> Self::Point {
        Self::scalar_mult(scalar, &Self::BASE_POINT)
            .expect("scalar_mult_base always produce valid points")
    }

    fn point_from_bytes(bytes: &Self::PointBytes) -> Option<Self::Point>;

    fn point_to_bytes(point: &Self::Point) -> Self::PointBytes;

    fn shared_secret_bytes(point: &Self::Point) -> Self::SharedSecretBytes;

    fn scalar_from_bytes(bytes: &Self::ScalarBytes) -> Option<Self::Scalar>;

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes;

    fn scalar_mult(scalar: &Self::Scalar, point: &Self::Point) -> Option<Self::Point>;
}

pub trait EcdsaCurve: EllipticCurve {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    BigEndian,
    LittleEndian,
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
    + Div<Output = Self>
    + DivAssign
    + Neg<Output = Self>
    + From<Self::Bytes>
    + Into<Self::Bytes>
    + From<u32>
{
    const CAPACITY: usize;
    const BYTE_ORDER: ByteOrder;

    const ZERO: Self;
    const ONE: Self;

    type Bytes: ByteArray;

    fn swap(a: &mut Self, b: &mut Self, condition: Choice);

    fn select(a: &Self, b: &Self, condition: Choice) -> Self;

    fn assign(&mut self, other: &Self, condition: Choice) {
        *self = Self::select(self, other, condition);
    }

    fn ct_eq(&self, other: &Self) -> Choice;

    fn square(self) -> Self;

    fn square2(self) -> Self {
        let square = self.square();
        square + square
    }

    fn double_value(self) -> Self {
        self + self
    }

    fn invert(self) -> Self;

    fn sqrt(self, b: Self) -> (Self, Choice);
}

pub trait Hasher: Init + Digest {
    const BLOCK_SIZE: usize;

    type Block: ByteArray;

    fn digest(message: &[u8]) -> Self::Output;
}

pub trait Init {
    fn new() -> Self;
}

pub trait KeyInit {
    fn new(key: &[u8]) -> Self;
}

pub trait Mac: KeyInit + Digest {
    fn verify(self, code: &Self::Output) -> bool;
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

pub trait MontgomeryParams<const LIMBS: usize>: Copy + Clone {
    const MOD: [u64; LIMBS];
    const ONE: [u64; LIMBS];
    const R2: [u64; LIMBS];
    const N0: u64;
}

pub trait Prf: KeyInit + Digest {}

pub trait StreamCipher {
    const KEY_SIZE: usize;
    const NONCE_SIZE: usize;

    type Key: ByteArray;
    type Nonce: ByteArray;

    fn new(key: &Self::Key, nonce: &Self::Nonce) -> Self;

    fn apply_keystream(&mut self, message: &mut [u8]);
}

pub trait SeedableCryptoRng: CryptoRng + Sized {
    fn new(seed: &[u8]) -> Self;

    fn reseed(&mut self, seed: &[u8]) {
        *self = Self::new(seed);
    }
}

pub trait SeekableStreamCipher: StreamCipher {
    const SEED_SIZE: usize;

    type Seed: ByteArray;

    fn seed(seed: &Self::Seed) -> Self;

    fn seek(&mut self, counter: u32);
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

pub trait Xof: Init {
    type Reader: XofReader;

    fn digest(message: &[u8], output: &mut [u8]);

    fn update(&mut self, message: &[u8]);

    fn finalize_into(self, output: &mut [u8]);

    fn finalize_xof(self) -> Self::Reader;
}

pub trait XofReader {
    fn read(&mut self, output: &mut [u8]);
}

pub(crate) trait Sealed {}

impl<const N: usize> Sealed for [u8; N] {}

impl<const N: usize> ByteArray for [u8; N] {
    const SIZE: usize = N;

    fn new() -> Self {
        [0u8; N]
    }

    fn from_slice(slice: &[u8]) -> Self {
        Self::from_slice_checked(slice).expect("Slice size matches array size")
    }

    fn from_slice_checked(slice: &[u8]) -> Option<Self> {
        Self::try_from(slice).ok()
    }
}
