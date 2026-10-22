macro_rules! impl_field_arithmetic {
    ($field:ident, $size:literal, $byte_order:expr, $bits:literal, $modulus:expr, $width:literal) => {
        pub struct $field<A: $crate::traits::FieldArithmetic<Bytes = [u8; $size]>>(
            [u8; $size],
            core::marker::PhantomData<A>,
        );

        impl<A> Clone for $field<A>
        where
            A: $crate::traits::FieldArithmetic<Bytes = [u8; $size]>,
        {
            fn clone(&self) -> Self {
                *self
            }
        }

        impl<A> Copy for $field<A> where A: $crate::traits::FieldArithmetic<Bytes = [u8; $size]> {}

        impl<A> $field<A>
        where
            A: $crate::traits::FieldArithmetic<Bytes = [u8; $size]>,
        {
            const MODULUS: [u8; $size] = $modulus;
            const ZERO: Self = Self::from_bytes(&[0; $size]);
            const ONE: Self = {
                let mut bytes = [0; $size];
                bytes[match $byte_order {
                    $crate::traits::ByteOrder::BigEndian => $size - 1,
                    $crate::traits::ByteOrder::LittleEndian => 0,
                }] = 1;
                Self::from_bytes(&bytes)
            };

            const fn from_bytes(bytes: &[u8; $size]) -> Self {
                Self(*bytes, core::marker::PhantomData)
            }

            const fn table_from_bytes(table: &[[[u8; $size]; $width]; 8]) -> [[Self; $width]; 8] {
                let mut result = [[Self::ZERO; $width]; 8];
                let mut i = 0;
                while i < 8 {
                    let mut j = 0;
                    while j < $width {
                        result[i][j] = Self::from_bytes(&table[i][j]);
                        j += 1;
                    }
                    i += 1;
                }
                result
            }

            fn reduce(mut bytes: [u8; $size]) -> Self {
                let top = match $byte_order {
                    $crate::traits::ByteOrder::BigEndian => 0,
                    $crate::traits::ByteOrder::LittleEndian => $size - 1,
                };
                bytes[top] &= u8::MAX >> (8 * $size - $bits);
                let mut difference = [0; $size];
                let mut borrow = 0u16;
                for i in 0..$size {
                    let j = match $byte_order {
                        $crate::traits::ByteOrder::BigEndian => $size - 1 - i,
                        $crate::traits::ByteOrder::LittleEndian => i,
                    };
                    let d = (bytes[j] as u16)
                        .wrapping_sub(Self::MODULUS[j] as u16)
                        .wrapping_sub(borrow);
                    difference[j] = d as u8;
                    borrow = d >> 15;
                }
                let subtract = !$crate::utils::Choice::nonzero(borrow as u8);
                subtract.assign(&mut bytes, &difference);
                Self::from_bytes(&bytes)
            }
        }

        impl<A> core::ops::Add for $field<A>
        where
            A: $crate::traits::FieldArithmetic<Bytes = [u8; $size]>,
        {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                Self::from_bytes(&A::add(&self.0, &rhs.0))
            }
        }

        impl<A> core::ops::AddAssign for $field<A>
        where
            A: $crate::traits::FieldArithmetic<Bytes = [u8; $size]>,
        {
            fn add_assign(&mut self, rhs: Self) {
                *self = *self + rhs;
            }
        }

        impl<A> core::ops::Sub for $field<A>
        where
            A: $crate::traits::FieldArithmetic<Bytes = [u8; $size]>,
        {
            type Output = Self;

            fn sub(self, rhs: Self) -> Self::Output {
                Self::from_bytes(&A::sub(&self.0, &rhs.0))
            }
        }

        impl<A> core::ops::SubAssign for $field<A>
        where
            A: $crate::traits::FieldArithmetic<Bytes = [u8; $size]>,
        {
            fn sub_assign(&mut self, rhs: Self) {
                *self = *self - rhs;
            }
        }

        impl<A> core::ops::Mul for $field<A>
        where
            A: $crate::traits::FieldArithmetic<Bytes = [u8; $size]>,
        {
            type Output = Self;

            fn mul(self, rhs: Self) -> Self::Output {
                Self::from_bytes(&A::mul(&self.0, &rhs.0))
            }
        }

        impl<A> core::ops::MulAssign for $field<A>
        where
            A: $crate::traits::FieldArithmetic<Bytes = [u8; $size]>,
        {
            fn mul_assign(&mut self, rhs: Self) {
                *self = *self * rhs;
            }
        }

        impl<A> core::ops::Neg for $field<A>
        where
            A: $crate::traits::FieldArithmetic<Bytes = [u8; $size]>,
        {
            type Output = Self;

            fn neg(self) -> Self::Output {
                Self::ZERO - self
            }
        }

        impl<A> From<[u8; $size]> for $field<A>
        where
            A: $crate::traits::FieldArithmetic<Bytes = [u8; $size]>,
        {
            fn from(bytes: [u8; $size]) -> Self {
                Self::reduce(bytes)
            }
        }

        impl<A> From<$field<A>> for [u8; $size]
        where
            A: $crate::traits::FieldArithmetic<Bytes = [u8; $size]>,
        {
            fn from(value: $field<A>) -> Self {
                value.0
            }
        }
    };
}

pub(crate) use impl_field_arithmetic;
