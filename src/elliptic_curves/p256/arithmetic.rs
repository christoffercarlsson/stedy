use {
    super::{
        P256,
        field::{pow_p_minus_3_div_4, pow2n, sqrt},
    },
    crate::{
        elliptic_curves::impl_field_arithmetic,
        traits::{ByteOrder, FieldArithmetic, FieldElement, WeierstrassParams},
        utils::Choice,
    },
};

impl_field_arithmetic!(
    FieldP256With,
    32,
    ByteOrder::BigEndian,
    256,
    [
        255, 255, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255
    ],
    2
);

impl<A: FieldArithmetic<Bytes = [u8; 32]>> FieldElement for FieldP256With<A> {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    const CAPACITY: usize = 255;
    const BYTE_ORDER: ByteOrder = ByteOrder::BigEndian;

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
        self * pow2n(pow_p_minus_3_div_4(self), 2)
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        sqrt(self, b)
    }
}

impl<A: FieldArithmetic<Bytes = [u8; 32]>> WeierstrassParams<FieldP256With<A>>
    for FieldP256With<A>
{
    const A: FieldP256With<A> = FieldP256With::from_bytes(&P256::A);
    const B: FieldP256With<A> = FieldP256With::from_bytes(&P256::B);
    const BASE_POINT_X: FieldP256With<A> = FieldP256With::from_bytes(&P256::BASE_POINT_X);
    const BASE_POINT_Y: FieldP256With<A> = FieldP256With::from_bytes(&P256::BASE_POINT_Y);
    const BASE_NAF: [[FieldP256With<A>; 2]; 8] = FieldP256With::table_from_bytes(&P256::BASE_NAF);
    const BASE_COMB_LOW: [[FieldP256With<A>; 2]; 8] =
        FieldP256With::table_from_bytes(&P256::BASE_COMB_LOW);
    const BASE_COMB_HIGH: [[FieldP256With<A>; 2]; 8] =
        FieldP256With::table_from_bytes(&P256::BASE_COMB_HIGH);

    type PointBytes = [u8; 33];
}
