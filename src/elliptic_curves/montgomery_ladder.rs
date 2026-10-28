use {
    crate::{
        Error,
        traits::{ByteArray, EllipticCurve, FieldElement, MontgomeryParams},
        utils::{Choice, Secret},
    },
    core::marker::PhantomData,
};

pub struct MontgomeryLadder<F>
where
    F: FieldElement + MontgomeryParams<F>,
{
    _marker: PhantomData<F>,
}

#[derive(Clone)]
pub struct MontgomeryScalar<F>(Secret<F::PointBytes>)
where
    F: FieldElement + MontgomeryParams<F>;

impl<F> MontgomeryLadder<F>
where
    F: FieldElement + MontgomeryParams<F>,
{
    const TOP: usize = F::BITS - 1;

    fn clamp(bytes: &mut F::PointBytes) {
        bytes[0] &= !(F::COFACTOR - 1);
        Self::truncate(bytes);
        bytes[Self::TOP / 8] |= 1 << (Self::TOP % 8);
    }

    fn truncate(bytes: &mut F::PointBytes) {
        bytes[Self::TOP / 8] &= u8::MAX >> (7 - Self::TOP % 8);
    }

    fn ladder(scalar: &MontgomeryScalar<F>, point: &F) -> F {
        const {
            assert!(
                F::COFACTOR.is_power_of_two(),
                "the cofactor is a power of two"
            );
        }
        const {
            assert!(
                F::BITS <= 8 * F::PointBytes::SIZE,
                "the scalar bits fit in the encoding"
            );
        }
        let mut scalar = scalar.0.clone();
        Self::clamp(scalar.get_mut());
        let scalar = scalar.get();
        let x1 = *point;
        let mut x2 = F::ONE;
        let mut z2 = F::ZERO;
        let mut x3 = *point;
        let mut z3 = F::ONE;
        let mut swap = Choice::FALSE;
        for i in (0..F::BITS).rev() {
            let bit = Choice::nonzero((scalar[i / 8] >> (i % 8)) & 1);
            swap ^= bit;
            F::swap(&mut x2, &mut x3, swap);
            F::swap(&mut z2, &mut z3, swap);
            swap = bit;
            let a = x2 + z2;
            let aa = a.square();
            let b = x2 - z2;
            let bb = b.square();
            let e = aa - bb;
            let c = x3 + z3;
            let d = x3 - z3;
            let da = d * a;
            let cb = c * b;
            x3 = (da + cb).square();
            z3 = x1 * (da - cb).square();
            x2 = aa * bb;
            z2 = e * (aa + F::mul_a24(e));
        }
        F::swap(&mut x2, &mut x3, swap);
        F::swap(&mut z2, &mut z3, swap);
        x2 * z2.invert()
    }
}

impl<F> EllipticCurve for MontgomeryLadder<F>
where
    F: FieldElement + MontgomeryParams<F>,
{
    type Point = F;
    type Scalar = MontgomeryScalar<F>;
    type PointBytes = F::PointBytes;
    type ScalarBytes = F::PointBytes;
    type SharedSecretBytes = F::PointBytes;

    fn point_from_bytes(bytes: &Self::PointBytes) -> Result<Self::Point, Error> {
        let mut bytes = *bytes;
        Self::truncate(&mut bytes);
        Ok(F::point_from_bytes(&bytes))
    }

    fn point_to_bytes(point: &Self::Point) -> Self::PointBytes {
        F::point_to_bytes(point)
    }

    fn shared_secret_bytes(point: &Self::Point) -> Self::SharedSecretBytes {
        F::point_to_bytes(point)
    }

    fn scalar_from_bytes(bytes: &Self::ScalarBytes) -> Result<Self::Scalar, Error> {
        Ok(MontgomeryScalar(Secret::from(*bytes)))
    }

    fn scalar_to_bytes(scalar: &Self::Scalar) -> Self::ScalarBytes {
        *scalar.0.get()
    }

    fn scalar_mult_base(scalar: &Self::Scalar) -> Self::Point {
        Self::ladder(scalar, &F::BASE_POINT)
    }

    fn scalar_mult(scalar: &Self::Scalar, point: &Self::Point) -> Result<Self::Point, Error> {
        let u = Self::ladder(scalar, point);
        if u.ct_eq(&F::ZERO).to_bool() {
            Err(Error::InvalidKey)
        } else {
            Ok(u)
        }
    }
}
