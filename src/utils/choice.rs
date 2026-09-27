use {
    crate::traits::Sealed,
    core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not},
};

#[cfg_attr(all(target_arch = "aarch64", not(miri)), path = "choice/aarch64.rs")]
#[cfg_attr(
    all(any(target_arch = "x86", target_arch = "x86_64"), not(miri)),
    path = "choice/x86.rs"
)]
#[cfg_attr(
    any(
        not(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")),
        miri
    ),
    path = "choice/soft.rs"
)]
mod backend;

#[derive(Clone, Copy)]
pub struct Choice(u8);

impl Choice {
    pub const FALSE: Self = Self(0);
    pub const TRUE: Self = Self(1);

    pub fn nonzero<T: Cmov>(value: T) -> Self {
        value.is_nonzero()
    }

    pub fn eq<T: Cmov>(a: T, b: T) -> Self {
        !(a ^ b).is_nonzero()
    }

    pub fn eq_slice<T: Cmov>(a: &[T], b: &[T]) -> Self {
        let difference = a
            .iter()
            .zip(b)
            .fold(T::default(), |difference, (&x, &y)| difference | (x ^ y));
        Self::eq(a.len(), b.len()) & !difference.is_nonzero()
    }

    pub fn less_than<T: Unsigned>(a: T, b: T) -> Self {
        a.is_less_than(b)
    }

    pub fn select<T: Cmov>(self, a: T, b: T) -> T {
        let mut selected = a;
        selected.assign(b, self);
        selected
    }

    pub fn assign<T: Cmov>(self, dst: &mut [T], src: &[T]) {
        T::assign_slice(dst, src, self);
    }

    pub fn swap<T: Cmov>(self, a: &mut [T], b: &mut [T]) {
        let mask = T::mask(self);
        for (a, b) in a.iter_mut().zip(b) {
            let difference = mask & (*a ^ *b);
            *a = *a ^ difference;
            *b = *b ^ difference;
        }
    }

    pub fn mask<T: Cmov>(self) -> T {
        T::mask(self)
    }

    pub fn to_bool(self) -> bool {
        backend::opaque(u32::from(self.0)) != 0
    }
}

impl Not for Choice {
    type Output = Self;

    fn not(self) -> Self {
        Self(self.0 ^ 1)
    }
}

impl BitAnd for Choice {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for Choice {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl BitOr for Choice {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Choice {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitXor for Choice {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for Choice {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

#[allow(private_bounds)]
pub trait Cmov:
    Copy + Default + BitAnd<Output = Self> + BitOr<Output = Self> + BitXor<Output = Self> + Sealed
{
    fn is_nonzero(self) -> Choice;

    fn mask(choice: Choice) -> Self;

    fn assign(&mut self, src: Self, choice: Choice);

    fn assign_slice(dst: &mut [Self], src: &[Self], choice: Choice) {
        let mask = Self::mask(choice);
        for (dst, src) in dst.iter_mut().zip(src) {
            *dst = *dst ^ (mask & (*dst ^ *src));
        }
    }
}

#[allow(private_bounds)]
pub trait Unsigned: Cmov {
    fn is_less_than(self, other: Self) -> Choice;
}

trait Backend: Copy {
    fn assign(dst: &mut Self, src: Self, condition: u8);
}

macro_rules! impl_backend {
    ($($t:ty),* $(,)?) => {$(
        impl Sealed for $t {}

        impl Cmov for $t {
            fn is_nonzero(self) -> Choice {
                let nonzero = (self | self.wrapping_neg()) >> (<$t>::BITS - 1);
                Choice(backend::opaque(nonzero as u32) as u8)
            }

            fn mask(choice: Choice) -> Self {
                (choice.0 as $t).wrapping_neg()
            }

            fn assign(&mut self, src: Self, choice: Choice) {
                Backend::assign(self, src, choice.0);
            }
        }
    )*};
}

macro_rules! impl_via {
    ($($t:ty => $u:ty),* $(,)?) => {$(
        impl Sealed for $t {}

        impl Cmov for $t {
            fn is_nonzero(self) -> Choice {
                (self as $u).is_nonzero()
            }

            fn mask(choice: Choice) -> Self {
                <$u>::mask(choice) as $t
            }

            fn assign(&mut self, src: Self, choice: Choice) {
                let mut wide = *self as $u;
                wide.assign(src as $u, choice);
                *self = wide as $t;
            }
        }
    )*};
}

macro_rules! impl_unsigned {
    ($($t:ty),* $(,)?) => {$(
        impl Unsigned for $t {
            fn is_less_than(self, other: Self) -> Choice {
                let (_, borrow) = self.overflowing_sub(other);
                Choice(u8::from(borrow))
            }
        }
    )*};
}

impl_backend!(u32, u64);

impl_via!(u8 => u16, u16 => u32, i8 => u8, i16 => u16, i32 => u32, i64 => u64, i128 => u128, isize => usize);

#[cfg(target_pointer_width = "32")]
impl_via!(usize => u32);

#[cfg(target_pointer_width = "64")]
impl_via!(usize => u64);

impl_unsigned!(u8, u16, u32, u64, u128, usize);

impl Sealed for u128 {}

impl Cmov for u128 {
    fn is_nonzero(self) -> Choice {
        (self as u64 | (self >> 64) as u64).is_nonzero()
    }

    fn mask(choice: Choice) -> Self {
        (choice.0 as u128).wrapping_neg()
    }

    fn assign(&mut self, src: Self, choice: Choice) {
        let mut low = *self as u64;
        let mut high = (*self >> 64) as u64;
        low.assign(src as u64, choice);
        high.assign((src >> 64) as u64, choice);
        *self = u128::from(low) | (u128::from(high) << 64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select() {
        for (a, b) in [(0u8, 255u8), (255, 0), (7, 7), (1, 2)] {
            assert_eq!(Choice::FALSE.select(a, b), a);
            assert_eq!(Choice::TRUE.select(a, b), b);
        }
        assert_eq!(Choice::FALSE.select(u16::MAX, 1), u16::MAX);
        assert_eq!(Choice::TRUE.select(u16::MAX, 1), 1);
        assert_eq!(Choice::FALSE.select(u32::MAX, 1), u32::MAX);
        assert_eq!(Choice::TRUE.select(u32::MAX, 1), 1);
        assert_eq!(Choice::FALSE.select(u64::MAX, 1), u64::MAX);
        assert_eq!(Choice::TRUE.select(u64::MAX, 1), 1);
        assert_eq!(Choice::FALSE.select(u128::MAX, 1), u128::MAX);
        assert_eq!(Choice::TRUE.select(u128::MAX, 1), 1);
        assert_eq!(Choice::FALSE.select(usize::MAX, 1), usize::MAX);
        assert_eq!(Choice::TRUE.select(usize::MAX, 1), 1);
        assert_eq!(Choice::FALSE.select(-1i8, 1), -1);
        assert_eq!(Choice::TRUE.select(-1i8, 1), 1);
        assert_eq!(Choice::FALSE.select(i32::MIN, i32::MAX), i32::MIN);
        assert_eq!(Choice::TRUE.select(i32::MIN, i32::MAX), i32::MAX);
        assert_eq!(Choice::FALSE.select(i64::MIN, -7), i64::MIN);
        assert_eq!(Choice::TRUE.select(i64::MIN, -7), -7);
        assert_eq!(Choice::TRUE.select(i128::MIN, i128::MAX), i128::MAX);
    }

    #[test]
    fn test_eq_and_nonzero() {
        assert!(Choice::eq(0u64, 0).to_bool());
        assert!(!Choice::eq(1u64, 2).to_bool());
        assert!(Choice::eq(u128::MAX, u128::MAX).to_bool());
        assert!(!Choice::eq(u128::MAX, u128::MAX - 1).to_bool());
        assert!(Choice::eq(-5i32, -5).to_bool());
        assert!(!Choice::eq(-5i32, 5).to_bool());
        assert!(!Choice::nonzero(0u8).to_bool());
        assert!(Choice::nonzero(1u8).to_bool());
        assert!(Choice::nonzero(128u8).to_bool());
        assert!(Choice::nonzero(1u64 << 63).to_bool());
        assert!(Choice::nonzero(u64::MAX).to_bool());
        assert!(Choice::nonzero(-1i32).to_bool());
        assert!(Choice::nonzero(i32::MIN).to_bool());
        assert!(!Choice::nonzero(0i128).to_bool());
        assert!(Choice::nonzero(1usize).to_bool());
    }

    #[test]
    fn test_less_than() {
        assert!(Choice::less_than(0u8, 1).to_bool());
        assert!(!Choice::less_than(1u8, 0).to_bool());
        assert!(!Choice::less_than(255u8, 255).to_bool());
        assert!(Choice::less_than(0u8, 255).to_bool());
        assert!(Choice::less_than(u64::MAX - 1, u64::MAX).to_bool());
        assert!(!Choice::less_than(u64::MAX, 0).to_bool());
        assert!(Choice::less_than(0u128, u128::MAX).to_bool());
        assert!(!Choice::less_than(7usize, 7).to_bool());
    }

    #[test]
    fn test_eq_slice() {
        let a = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut b = a;
        assert!(Choice::eq_slice(&a, &b).to_bool());
        b[8] = 0;
        assert!(!Choice::eq_slice(&a, &b).to_bool());
        assert!(!Choice::eq_slice(&a, &a[..8]).to_bool());
        assert!(Choice::eq_slice::<u8>(&[], &[]).to_bool());
        let words = [u64::MAX, 0, 1 << 63];
        assert!(Choice::eq_slice(&words, &words).to_bool());
        assert!(!Choice::eq_slice(&words, &[u64::MAX, 0, 1 << 62]).to_bool());
    }

    #[test]
    fn test_assign_and_swap() {
        let src: [u8; 19] = core::array::from_fn(|i| 200 + i as u8);
        let mut dst = [7u8; 19];
        Choice::FALSE.assign(&mut dst, &src);
        assert_eq!(dst, [7u8; 19]);
        Choice::TRUE.assign(&mut dst, &src);
        assert_eq!(dst, src);
        let mut a = [1u32, 2, 3];
        let mut b = [4u32, 5, 6];
        Choice::FALSE.swap(&mut a, &mut b);
        assert_eq!((a, b), ([1, 2, 3], [4, 5, 6]));
        Choice::TRUE.swap(&mut a, &mut b);
        assert_eq!((a, b), ([4, 5, 6], [1, 2, 3]));
        let mut words = [i64::MIN, -1];
        Choice::TRUE.assign(&mut words, &[3, 4]);
        assert_eq!(words, [3, 4]);
    }

    #[test]
    fn test_mask() {
        assert_eq!(Choice::TRUE.mask::<u8>(), 0xff);
        assert_eq!(Choice::FALSE.mask::<u8>(), 0);
        assert_eq!(Choice::TRUE.mask::<u64>(), u64::MAX);
        assert_eq!(Choice::TRUE.mask::<u128>(), u128::MAX);
        assert_eq!(Choice::TRUE.mask::<i32>(), -1);
        assert_eq!(Choice::FALSE.mask::<i32>(), 0);
        assert_eq!((!Choice::TRUE).mask::<u16>(), 0);
        assert_eq!((Choice::TRUE & Choice::FALSE).mask::<u16>(), 0);
        assert_eq!((Choice::TRUE | Choice::FALSE).mask::<u16>(), u16::MAX);
        assert_eq!((Choice::TRUE ^ Choice::TRUE).mask::<u16>(), 0);
    }
}
