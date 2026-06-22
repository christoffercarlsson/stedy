use {
    crate::traits::{FieldElement, WeierstrassParams},
    core::{
        cmp::PartialEq,
        ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    },
};

#[cfg_attr(target_pointer_width = "32", path = "field32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field64.rs")]
mod field_p521;

pub use field_p521::FieldP521;

impl FieldP521 {
    fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 66];
        let size = slice.len().min(66);
        bytes[..size].copy_from_slice(&slice[..size]);
        Self::from(&bytes)
    }

    fn invert(self) -> Self {
        let x = self;
        x * x.pow25191().pow2n(2)
    }

    fn pow25191(self) -> Self {
        let x = self;
        let x2 = x.square();
        let x3 = x * x2;
        let x6 = x3.square();
        let x7 = x * x6;
        let x63 = x7 * x7.pow2n(3);
        let x127 = x * x63.square();
        let x8 = x * x127.square();
        let x16 = x8 * x8.pow2n(8);
        let x32 = x16 * x16.pow2n(16);
        let x64 = x32 * x32.pow2n(32);
        let x128 = x64 * x64.pow2n(64);
        let x256 = x128 * x128.pow2n(128);
        let x512 = x256 * x256.pow2n(256);
        x127 * x512.pow2n(7)
    }

    fn pow2n(self, n: usize) -> Self {
        let mut x = self.square();
        for _ in 1..n {
            x = x.square();
        }
        x
    }

    fn sqrt(self, b: Self) -> (Self, u64) {
        let u = self;
        let v = b;
        let v2 = v.square();
        let v3 = v2 * v;
        let r = u * v * (u * v3).pow25191();
        let c = v * r.square();
        let valid = (u == c) as u64;
        let r = Self::select(&Self::ZERO, &r, valid);
        (r, valid)
    }
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

impl Div for FieldP521 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.mul(rhs.invert())
    }
}

impl DivAssign for FieldP521 {
    fn div_assign(&mut self, rhs: Self) {
        *self = self.div(rhs);
    }
}

impl PartialEq for FieldP521 {
    fn eq(&self, other: &Self) -> bool {
        self.eq(other)
    }
}

impl Eq for FieldP521 {}

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

impl From<&[u8]> for FieldP521 {
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}

impl From<u32> for FieldP521 {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
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

    type Bytes = [u8; 66];

    fn swap(a: &mut Self, b: &mut Self, condition: u64) {
        Self::swap(a, b, condition);
    }

    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        Self::select(a, b, condition)
    }

    fn square(self) -> Self {
        self.square()
    }

    fn invert(self) -> Self {
        self.invert()
    }

    fn sqrt(self, b: Self) -> (Self, u64) {
        self.sqrt(b)
    }
}

impl WeierstrassParams<FieldP521> for FieldP521 {
    const A: FieldP521 = FieldP521::from_limbs([
        288230376151711740,
        288230376151711743,
        288230376151711743,
        288230376151711743,
        288230376151711743,
        288230376151711743,
        288230376151711743,
        288230376151711743,
        144115188075855871,
    ]);
    const B: FieldP521 = FieldP521::from_limbs([
        235629552700768000,
        69772874559077499,
        3329025324905303,
        92238005991659851,
        112292065468356921,
        174731625923158628,
        23660296994760121,
        173527443700089562,
        22963569744252444,
    ]);
    const BASE_POINT_X: FieldP521 = FieldP521::from_limbs([
        107662193291804006,
        156764387973048062,
        5200896066446132,
        135037196563642487,
        30202750027516766,
        94555012806093784,
        97746763129557904,
        263238996462508174,
        55878890433217540,
    ]);
    const BASE_POINT_Y: FieldP521 = FieldP521::from_limbs([
        53643482783376976,
        224091089528721442,
        256727146720269139,
        172680296574162242,
        227218914761240178,
        137026748380081989,
        275209519478621333,
        216191964133904561,
        78875843521714747,
    ]);

    type PointBytes = [u8; 67];
}
