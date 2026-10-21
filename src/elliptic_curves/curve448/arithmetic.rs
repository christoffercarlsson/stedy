use {
    super::{
        Curve448, Edwards448,
        field::{invert, sqrt},
    },
    crate::{
        elliptic_curves::impl_field_arithmetic,
        traits::{ByteOrder, EdwardsParams, FieldArithmetic, FieldElement, MontgomeryParams},
        utils::Choice,
    },
};

impl_field_arithmetic!(
    Field448With,
    56,
    ByteOrder::LittleEndian,
    448,
    [
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255
    ],
    3
);

impl<A: FieldArithmetic<Bytes = [u8; 56]>> Field448With<A> {
    const R: Self = Self::from_bytes(&[
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
}

impl<A: FieldArithmetic<Bytes = [u8; 56]>> From<[u8; 57]> for Field448With<A> {
    fn from(value: [u8; 57]) -> Self {
        let (bytes, top) = value.split_at(56);
        let bytes: [u8; 56] = bytes
            .try_into()
            .expect("the encoding holds a 56-byte element");
        Self::from(bytes) + Self::from_u32(top[0] as u32) * Self::R
    }
}

impl<A: FieldArithmetic<Bytes = [u8; 56]>> From<Field448With<A>> for [u8; 57] {
    fn from(value: Field448With<A>) -> Self {
        let mut bytes = [0u8; 57];
        bytes[..56].copy_from_slice(&value.0);
        bytes
    }
}

impl<A: FieldArithmetic<Bytes = [u8; 56]>> FieldElement for Field448With<A> {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    const CAPACITY: usize = 447;
    const BYTE_ORDER: ByteOrder = ByteOrder::LittleEndian;

    type Bytes = [u8; 57];

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
        sqrt(self, b)
    }

    fn from_u32(value: u32) -> Self {
        let mut bytes = [0u8; 56];
        bytes[..4].copy_from_slice(&value.to_le_bytes());
        Self::from(bytes)
    }
}

impl<A: FieldArithmetic<Bytes = [u8; 56]>> EdwardsParams<Field448With<A>> for Field448With<A> {
    const A: i8 = Edwards448::A;
    const COFACTOR: u8 = Edwards448::COFACTOR;
    const DOMAIN: &'static [u8] = Edwards448::DOMAIN;
    const DOMAIN_PURE: bool = Edwards448::DOMAIN_PURE;
    const D: Self = Self::from_bytes(&Edwards448::D);
    const D2: Self = Self::from_bytes(&Edwards448::D2);
    const BASE_POINT_X: Self = Self::from_bytes(&Edwards448::BASE_POINT_X);
    const BASE_POINT_Y: Self = Self::from_bytes(&Edwards448::BASE_POINT_Y);
    const BASE_POINT_T: Self = Self::from_bytes(&Edwards448::BASE_POINT_T);
    const BASE_COMB_LOW: [[Self; 3]; 8] = Self::table_from_bytes(&Edwards448::BASE_COMB_LOW);
    const BASE_COMB_HIGH: [[Self; 3]; 8] = Self::table_from_bytes(&Edwards448::BASE_COMB_HIGH);
}

impl<A: FieldArithmetic<Bytes = [u8; 56]>> MontgomeryParams<Field448With<A>> for Field448With<A> {
    const BITS: usize = Curve448::BITS;
    const COFACTOR: u8 = Curve448::COFACTOR;
    const BASE_POINT: Self = Self::from_bytes(&Curve448::BASE_POINT);

    type PointBytes = [u8; 56];

    fn point_from_bytes(bytes: &Self::PointBytes) -> Self {
        Self::from(*bytes)
    }

    fn point_to_bytes(point: &Self) -> Self::PointBytes {
        point.0
    }

    fn mul_a24(element: Self) -> Self {
        element * Self::from_u32(Curve448::A24)
    }
}
