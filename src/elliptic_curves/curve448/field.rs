use {
    super::Edwards448,
    crate::{
        traits::{ByteOrder, EdwardsParams, FieldElement},
        utils::Choice,
    },
    core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[cfg_attr(target_pointer_width = "32", path = "field32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field64.rs")]
mod field448;

pub use field448::Field448;

impl Field448 {
    const R: Self = Self::from_limbs([1, 0, 0, 0, 1, 0, 0, 0]);

    pub(crate) const fn from_le_bytes(bytes: &[u8; 56]) -> Self {
        let (chunks, _) = bytes.as_chunks::<7>();
        let mut limbs = [0u64; 8];
        let mut i = 0;
        while i < 8 {
            let c = chunks[i];
            limbs[i] = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], 0]);
            i += 1;
        }
        Self::from_limbs(limbs)
    }

    const fn table_from_bytes(table: &[[[u8; 56]; 3]; 8]) -> [[Self; 3]; 8] {
        let mut result = [[Self::ZERO; 3]; 8];
        let mut i = 0;
        while i < 8 {
            result[i] = [
                Self::from_le_bytes(&table[i][0]),
                Self::from_le_bytes(&table[i][1]),
                Self::from_le_bytes(&table[i][2]),
            ];
            i += 1;
        }
        result
    }

    fn invert(self) -> Self {
        let x = self;
        x * x.pow_p_minus_3_div_4().pow2n(2)
    }

    fn pow_p_minus_3_div_4(self) -> Self {
        let x = self;
        let x2 = x * x.square();
        let x3 = x * x2.square();
        let x6 = x3 * x3.pow2n(3);
        let x12 = x6 * x6.pow2n(6);
        let x24 = x12 * x12.pow2n(12);
        let x27 = x3 * x24.pow2n(3);
        let x54 = x27 * x27.pow2n(27);
        let x108 = x54 * x54.pow2n(54);
        let x111 = x3 * x108.pow2n(3);
        let x222 = x111 * x111.pow2n(111);
        let x223 = x * x222.square();
        x222 * x223.pow2n(223)
    }

    fn pow2n(self, n: usize) -> Self {
        let mut x = self.square();
        for _ in 1..n {
            x = x.square();
        }
        x
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        let u = self;
        let v = b;
        let v2 = v.square();
        let v3 = v2 * v;
        let r = u * v * (u * v3).pow_p_minus_3_div_4();
        let c = v * r.square();
        let valid = u.ct_eq(&c);
        let r = Self::select(&Self::ZERO, &r, valid);
        (r, valid)
    }
}

impl Add for Field448 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl AddAssign for Field448 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Sub for Field448 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(rhs)
    }
}

impl SubAssign for Field448 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl Neg for Field448 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl Mul for Field448 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl MulAssign for Field448 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl From<&[u8; 57]> for Field448 {
    fn from(value: &[u8; 57]) -> Self {
        let (bytes, top) = value.split_at(56);
        let bytes = bytes.try_into().expect("Slice size matches array size");
        Self::from_le_bytes(bytes) + Self::from_u32(top[0] as u32) * Self::R
    }
}

impl From<[u8; 57]> for Field448 {
    fn from(value: [u8; 57]) -> Self {
        Self::from(&value)
    }
}

impl From<Field448> for [u8; 57] {
    fn from(value: Field448) -> Self {
        let mut bytes = [0u8; 57];
        bytes[..56].copy_from_slice(&value.to_le_bytes());
        bytes
    }
}

impl From<&Field448> for [u8; 57] {
    fn from(value: &Field448) -> Self {
        Self::from(*value)
    }
}

impl FieldElement for Field448 {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    const CAPACITY: usize = 447;
    const BYTE_ORDER: ByteOrder = ByteOrder::LittleEndian;

    type Bytes = [u8; 57];

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
        self.invert()
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        self.sqrt(b)
    }

    fn from_u32(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl EdwardsParams<Field448> for Field448 {
    const A: i8 = Edwards448::A;
    const DOMAIN: &'static [u8] = Edwards448::DOMAIN;
    const DOMAIN_PURE: bool = Edwards448::DOMAIN_PURE;
    const D: Self = Self::from_le_bytes(&Edwards448::D);
    const D2: Self = Self::from_le_bytes(&Edwards448::D2);
    const BASE_POINT_X: Self = Self::from_le_bytes(&Edwards448::BASE_POINT_X);
    const BASE_POINT_Y: Self = Self::from_le_bytes(&Edwards448::BASE_POINT_Y);
    const BASE_POINT_T: Self = Self::from_le_bytes(&Edwards448::BASE_POINT_T);
    const BASE_COMB_LOW: [[Self; 3]; 8] = Self::table_from_bytes(&Edwards448::BASE_COMB_LOW);
    const BASE_COMB_HIGH: [[Self; 3]; 8] = Self::table_from_bytes(&Edwards448::BASE_COMB_HIGH);
}
