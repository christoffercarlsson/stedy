use {
    super::{
        P521,
        field::{invert, sqrt},
    },
    crate::{
        elliptic_curves::impl_field_arithmetic,
        traits::{ByteOrder, FieldArithmetic, FieldElement, WeierstrassParams},
        utils::Choice,
    },
};

impl_field_arithmetic!(
    FieldP521With,
    66,
    ByteOrder::BigEndian,
    521,
    [
        1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
    ],
    2
);

impl<A> FieldElement for FieldP521With<A>
where
    A: FieldArithmetic<Bytes = [u8; 66]>,
{
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    const CAPACITY: usize = 520;
    const BYTE_ORDER: ByteOrder = ByteOrder::BigEndian;

    type Bytes = [u8; 66];

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
}

impl<A> WeierstrassParams<FieldP521With<A>> for FieldP521With<A>
where
    A: FieldArithmetic<Bytes = [u8; 66]>,
{
    const A: FieldP521With<A> = FieldP521With::from_bytes(&P521::A);
    const B: FieldP521With<A> = FieldP521With::from_bytes(&P521::B);
    const BASE_POINT_X: FieldP521With<A> = FieldP521With::from_bytes(&P521::BASE_POINT_X);
    const BASE_POINT_Y: FieldP521With<A> = FieldP521With::from_bytes(&P521::BASE_POINT_Y);
    const BASE_NAF: [[FieldP521With<A>; 2]; 8] = FieldP521With::table_from_bytes(&P521::BASE_NAF);
    const BASE_COMB_LOW: [[FieldP521With<A>; 2]; 8] =
        FieldP521With::table_from_bytes(&P521::BASE_COMB_LOW);
    const BASE_COMB_HIGH: [[FieldP521With<A>; 2]; 8] =
        FieldP521With::table_from_bytes(&P521::BASE_COMB_HIGH);

    type PointBytes = [u8; 67];
}
