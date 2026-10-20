use {
    super::{
        Curve25519, Edwards25519,
        field::{invert, sqrt},
    },
    crate::{
        elliptic_curves::impl_field_arithmetic,
        traits::{ByteOrder, EdwardsParams, FieldArithmetic, FieldElement, MontgomeryParams},
        utils::Choice,
    },
};

impl_field_arithmetic!(
    Field25519With,
    32,
    ByteOrder::LittleEndian,
    255,
    [
        237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127
    ],
    3
);

impl<A: FieldArithmetic<Bytes = [u8; 32]>> Field25519With<A> {
    const SQRT_M1: Self = Self::from_bytes(&[
        176, 160, 14, 74, 39, 27, 238, 196, 120, 228, 47, 173, 6, 24, 67, 47, 167, 215, 251, 61,
        153, 0, 77, 43, 11, 223, 193, 79, 128, 36, 131, 43,
    ]);
}

impl<A: FieldArithmetic<Bytes = [u8; 32]>> FieldElement for Field25519With<A> {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    const CAPACITY: usize = 254;
    const BYTE_ORDER: ByteOrder = ByteOrder::LittleEndian;

    type Bytes = [u8; 32];

    fn select(a: &Self, b: &Self, condition: Choice) -> Self {
        let mut selected = a.0;
        condition.assign(&mut selected, &b.0);
        Self::from_bytes(&selected)
    }

    fn square(self) -> Self {
        Self::from_bytes(&A::square(&self.0))
    }

    fn invert(self) -> Self {
        invert(self)
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        sqrt(self, b, Self::SQRT_M1)
    }
}

impl<A: FieldArithmetic<Bytes = [u8; 32]>> EdwardsParams<Field25519With<A>> for Field25519With<A> {
    const A: i8 = Edwards25519::A;
    const DOMAIN: &'static [u8] = Edwards25519::DOMAIN;
    const DOMAIN_PURE: bool = Edwards25519::DOMAIN_PURE;
    const D: Self = Self::from_bytes(&Edwards25519::D);
    const D2: Self = Self::from_bytes(&Edwards25519::D2);
    const BASE_POINT_X: Self = Self::from_bytes(&Edwards25519::BASE_POINT_X);
    const BASE_POINT_Y: Self = Self::from_bytes(&Edwards25519::BASE_POINT_Y);
    const BASE_POINT_T: Self = Self::from_bytes(&Edwards25519::BASE_POINT_T);
    const BASE_COMB_LOW: [[Self; 3]; 8] = Self::table_from_bytes(&Edwards25519::BASE_COMB_LOW);
    const BASE_COMB_HIGH: [[Self; 3]; 8] = Self::table_from_bytes(&Edwards25519::BASE_COMB_HIGH);
}

impl<A: FieldArithmetic<Bytes = [u8; 32]>> MontgomeryParams<Field25519With<A>>
    for Field25519With<A>
{
    const BITS: usize = Curve25519::BITS;
    const COFACTOR: u8 = Curve25519::COFACTOR;
    const BASE_POINT: Self = Self::from_bytes(&Curve25519::BASE_POINT);

    type PointBytes = [u8; 32];

    fn point_from_bytes(bytes: &Self::PointBytes) -> Self {
        Self::from(*bytes)
    }

    fn point_to_bytes(point: &Self) -> Self::PointBytes {
        point.0
    }

    fn mul_a24(element: Self) -> Self {
        element * Self::from_u32(Curve25519::A24)
    }
}
