use {
    super::{
        P384,
        field::{pow_p_minus_3_div_4, pow2n, sqrt},
    },
    crate::{
        elliptic_curves::impl_field_arithmetic,
        traits::{ByteOrder, FieldArithmetic, FieldElement, WeierstrassParams},
        utils::Choice,
    },
};

impl_field_arithmetic!(
    FieldP384With,
    48,
    ByteOrder::BigEndian,
    384,
    [
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255,
        0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255
    ],
    2
);

impl<A: FieldArithmetic<Bytes = [u8; 48]>> FieldElement for FieldP384With<A> {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    const CAPACITY: usize = 383;
    const BYTE_ORDER: ByteOrder = ByteOrder::BigEndian;

    type Bytes = [u8; 48];

    fn select(a: &Self, b: &Self, condition: Choice) -> Self {
        let mut selected = a.0;
        condition.assign(&mut selected, &b.0);
        Self::from_bytes(&selected)
    }

    fn invert(self) -> Self {
        self * pow2n(pow_p_minus_3_div_4(self), 2)
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        sqrt(self, b)
    }
}

impl<A: FieldArithmetic<Bytes = [u8; 48]>> WeierstrassParams<FieldP384With<A>>
    for FieldP384With<A>
{
    const A: FieldP384With<A> = FieldP384With::from_bytes(&P384::A);
    const B: FieldP384With<A> = FieldP384With::from_bytes(&P384::B);
    const BASE_POINT_X: FieldP384With<A> = FieldP384With::from_bytes(&P384::BASE_POINT_X);
    const BASE_POINT_Y: FieldP384With<A> = FieldP384With::from_bytes(&P384::BASE_POINT_Y);
    const BASE_NAF: [[FieldP384With<A>; 2]; 8] = FieldP384With::table_from_bytes(&P384::BASE_NAF);
    const BASE_COMB_LOW: [[FieldP384With<A>; 2]; 8] =
        FieldP384With::table_from_bytes(&P384::BASE_COMB_LOW);
    const BASE_COMB_HIGH: [[FieldP384With<A>; 2]; 8] =
        FieldP384With::table_from_bytes(&P384::BASE_COMB_HIGH);

    type PointBytes = [u8; 49];
}
