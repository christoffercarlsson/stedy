use {
    super::P521,
    crate::{
        traits::{ByteOrder, FieldElement, WeierstrassParams},
        utils::Choice,
    },
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[cfg_attr(target_pointer_width = "32", path = "field32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field64.rs")]
mod field_p521;

pub use field_p521::FieldP521;

impl FieldP521 {
    const fn from_bytes(bytes: &[u8; 66]) -> Self {
        const MASK: u64 = (1 << 58) - 1;
        const TOP_MASK: u64 = (1 << 57) - 1;
        let mut reversed = [0u8; 66];
        let mut i = 0;
        while i < 66 {
            reversed[i] = bytes[65 - i];
            i += 1;
        }
        let (chunks, remainder) = reversed.as_chunks::<8>();
        let mut words = [0u64; 8];
        let mut i = 0;
        while i < 8 {
            words[i] = u64::from_le_bytes(chunks[i]);
            i += 1;
        }
        let top_word = (remainder[0] as u64) | ((remainder[1] as u64 & 1) << 8);
        Self::from_limbs([
            words[0] & MASK,
            ((words[0] >> 58) | (words[1] << 6)) & MASK,
            ((words[1] >> 52) | (words[2] << 12)) & MASK,
            ((words[2] >> 46) | (words[3] << 18)) & MASK,
            ((words[3] >> 40) | (words[4] << 24)) & MASK,
            ((words[4] >> 34) | (words[5] << 30)) & MASK,
            ((words[5] >> 28) | (words[6] << 36)) & MASK,
            ((words[6] >> 22) | (words[7] << 42)) & MASK,
            ((words[7] >> 16) | (top_word << 48)) & TOP_MASK,
        ])
    }

    const fn table_from_bytes(table: &[[[u8; 66]; 2]; 8]) -> [[Self; 2]; 8] {
        let mut result = [[Self::ZERO; 2]; 8];
        let mut i = 0;
        while i < 8 {
            result[i] = [
                Self::from_bytes(&table[i][0]),
                Self::from_bytes(&table[i][1]),
            ];
            i += 1;
        }
        result
    }
}

pub(super) fn invert<F>(x: F) -> F
where
    F: FieldElement,
{
    x * pow2n(pow25191(x), 2)
}

fn pow25191<F>(x: F) -> F
where
    F: FieldElement,
{
    let x2 = x.square();
    let x3 = x * x2;
    let x6 = x3.square();
    let x7 = x * x6;
    let x63 = x7 * pow2n(x7, 3);
    let x127 = x * x63.square();
    let x8 = x * x127.square();
    let x16 = x8 * pow2n(x8, 8);
    let x32 = x16 * pow2n(x16, 16);
    let x64 = x32 * pow2n(x32, 32);
    let x128 = x64 * pow2n(x64, 64);
    let x256 = x128 * pow2n(x128, 128);
    let x512 = x256 * pow2n(x256, 256);
    x127 * pow2n(x512, 7)
}

fn pow2n<F>(x: F, n: usize) -> F
where
    F: FieldElement,
{
    let mut x = x.square();
    for _ in 1..n {
        x = x.square();
    }
    x
}

pub(super) fn sqrt<F>(u: F, v: F) -> (F, Choice)
where
    F: FieldElement,
{
    let v2 = v.square();
    let v3 = v2 * v;
    let r = u * v * pow25191(u * v3);
    let c = v * r.square();
    let valid = u.ct_eq(&c);
    let r = F::select(&F::ZERO, &r, valid);
    (r, valid)
}

impl Add for FieldP521 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl AddAssign for FieldP521 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Sub for FieldP521 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(rhs)
    }
}

impl SubAssign for FieldP521 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl Neg for FieldP521 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl Mul for FieldP521 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl MulAssign for FieldP521 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl From<&[u8; 66]> for FieldP521 {
    fn from(value: &[u8; 66]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<[u8; 66]> for FieldP521 {
    fn from(value: [u8; 66]) -> Self {
        Self::from(&value)
    }
}

impl From<FieldP521> for [u8; 66] {
    fn from(value: FieldP521) -> Self {
        value.to_bytes()
    }
}

impl From<&FieldP521> for [u8; 66] {
    fn from(value: &FieldP521) -> Self {
        Self::from(*value)
    }
}

impl FieldElement for FieldP521 {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    const CAPACITY: usize = 520;
    const BYTE_ORDER: ByteOrder = ByteOrder::BigEndian;

    type Bytes = [u8; 66];

    fn swap(a: &mut Self, b: &mut Self, condition: Choice) {
        Self::swap(a, b, condition);
    }

    fn select(a: &Self, b: &Self, condition: Choice) -> Self {
        Self::select(a, b, condition)
    }

    fn ct_eq(&self, other: &Self) -> Choice {
        self.ct_eq(other)
    }

    fn square(self) -> Self {
        self.square()
    }

    fn invert(self) -> Self {
        invert(self)
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        sqrt(self, b)
    }

    fn from_u32(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl WeierstrassParams<FieldP521> for FieldP521 {
    const A: FieldP521 = FieldP521::from_bytes(&P521::A);
    const B: FieldP521 = FieldP521::from_bytes(&P521::B);
    const BASE_POINT_X: FieldP521 = FieldP521::from_bytes(&P521::BASE_POINT_X);
    const BASE_POINT_Y: FieldP521 = FieldP521::from_bytes(&P521::BASE_POINT_Y);
    const BASE_NAF: [[FieldP521; 2]; 8] = FieldP521::table_from_bytes(&P521::BASE_NAF);
    const BASE_COMB_LOW: [[FieldP521; 2]; 8] = FieldP521::table_from_bytes(&P521::BASE_COMB_LOW);
    const BASE_COMB_HIGH: [[FieldP521; 2]; 8] = FieldP521::table_from_bytes(&P521::BASE_COMB_HIGH);

    type PointBytes = [u8; 67];
}
