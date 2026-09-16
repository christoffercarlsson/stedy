use core::{
    hint::black_box,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not},
};

pub(crate) trait CtWord:
    Copy
    + BitAnd<Output = Self>
    + BitAndAssign
    + BitOr<Output = Self>
    + BitOrAssign
    + BitXor<Output = Self>
    + BitXorAssign
    + Not<Output = Self>
{
    const ZERO: Self;

    fn mask(condition: u64) -> Self;

    fn msb(self) -> u64;

    fn nonzero(self) -> u64;

    fn to_u64(self) -> u64;
}

macro_rules! impl_ct_word {
    ($($t:ty => $u:ty),* $(,)?) => {$(
        impl CtWord for $t {
            const ZERO: Self = 0;

            #[inline(always)]
            fn mask(condition: u64) -> Self {
                (black_box(condition) as $t).wrapping_neg()
            }

            #[inline(always)]
            fn msb(self) -> u64 {
                ((self as $u) >> (<$u>::BITS - 1)) as u64
            }

            #[inline(always)]
            fn nonzero(self) -> u64 {
                let x = black_box(self as $u);
                ((x | x.wrapping_neg()) >> (<$u>::BITS - 1)) as u64
            }

            #[inline(always)]
            fn to_u64(self) -> u64 {
                (self as $u) as u64
            }
        }
    )*};
}

impl_ct_word!(u8 => u8, u16 => u16, u32 => u32, u64 => u64, usize => usize, i32 => u32, i64 => u64);

#[inline(always)]
pub(crate) fn choice(b: bool) -> u64 {
    black_box(b as u64)
}

#[inline(always)]
pub(crate) fn mask<W: CtWord>(condition: u64) -> W {
    W::mask(condition)
}

#[inline(always)]
pub(crate) fn msb<W: CtWord>(w: W) -> u64 {
    w.msb()
}

#[inline(always)]
pub(crate) fn eq_word<W: CtWord>(a: W, b: W) -> u64 {
    1 ^ (a ^ b).nonzero()
}

#[inline(always)]
pub(crate) fn lt_word<W: CtWord>(a: W, b: W) -> u64 {
    let a = black_box(a.to_u64());
    let b = black_box(b.to_u64());
    ((!a & b) | (!(a ^ b) & a.wrapping_sub(b))) >> 63
}

#[inline(always)]
pub(crate) fn select_word<W: CtWord>(a: W, b: W, condition: u64) -> W {
    let m = W::mask(condition);
    (a & !m) | (b & m)
}

#[inline(never)]
pub(crate) fn eq_limbs<W: CtWord>(a: &[W], b: &[W]) -> u64 {
    if a.len() != b.len() {
        return 0;
    }
    let mut acc = W::ZERO;
    for (&x, &y) in a.iter().zip(b) {
        acc |= black_box(x ^ y);
    }
    1 ^ acc.nonzero()
}

#[inline(never)]
pub(crate) fn is_zero_limbs<W: CtWord>(a: &[W]) -> u64 {
    let mut acc = W::ZERO;
    for &x in a {
        acc |= black_box(x);
    }
    1 ^ acc.nonzero()
}

#[inline(never)]
pub(crate) fn lt_limbs<W: CtWord>(a: &[W], b: &[W]) -> u64 {
    let mut borrow = 0u64;
    for (&x, &y) in a.iter().zip(b).rev() {
        let x = black_box(x.to_u64());
        let y = black_box(y.to_u64());
        let lt = lt_word(x, y);
        let eq = eq_word(x, y);
        borrow = lt | (eq & borrow);
    }
    borrow
}

#[inline(always)]
pub(crate) fn select_limbs<W: CtWord, const N: usize>(
    a: &[W; N],
    b: &[W; N],
    condition: u64,
) -> [W; N] {
    let m = W::mask(condition);
    let mut out = [W::ZERO; N];
    for i in 0..N {
        out[i] = (a[i] & !m) | (b[i] & m);
    }
    out
}

#[inline(always)]
pub(crate) fn swap_limbs<W: CtWord, const N: usize>(
    a: &mut [W; N],
    b: &mut [W; N],
    condition: u64,
) {
    let m = W::mask(condition);
    for i in 0..N {
        let t = m & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

#[inline(always)]
pub(crate) fn abs_i8(x: i8) -> (u8, u64) {
    let xn = black_box(x as i16);
    let sign = xn >> 15;
    let magnitude = ((xn ^ sign) - sign) as u8;
    (magnitude, (sign & 1) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask() {
        assert_eq!(mask::<u8>(0), 0);
        assert_eq!(mask::<u8>(1), u8::MAX);
        assert_eq!(mask::<u32>(1), u32::MAX);
        assert_eq!(mask::<u64>(1), u64::MAX);
        assert_eq!(mask::<i32>(1), -1);
        assert_eq!(mask::<i32>(0), 0);
    }

    #[test]
    fn test_msb() {
        assert_eq!(msb(0u64), 0);
        assert_eq!(msb(1u64 << 63), 1);
        assert_eq!(msb(u64::MAX >> 1), 0);
        assert_eq!(msb(1u32 << 31), 1);
        assert_eq!(msb(-1i32), 1);
        assert_eq!(msb(1i32), 0);
    }

    #[test]
    fn test_eq_word() {
        assert_eq!(eq_word(0u8, 0u8), 1);
        assert_eq!(eq_word(0u8, 1u8), 0);
        assert_eq!(eq_word(u64::MAX, u64::MAX), 1);
        assert_eq!(eq_word(u64::MAX, u64::MAX - 1), 0);
        assert_eq!(eq_word(-1i32, -1i32), 1);
        assert_eq!(eq_word(-1i32, 1i32), 0);
    }

    #[test]
    fn test_lt_word() {
        assert_eq!(lt_word(0u8, 1u8), 1);
        assert_eq!(lt_word(1u8, 0u8), 0);
        assert_eq!(lt_word(5u8, 5u8), 0);
        assert_eq!(lt_word(0u64, u64::MAX), 1);
        assert_eq!(lt_word(u64::MAX, 0u64), 0);
        assert_eq!(lt_word(u64::MAX - 1, u64::MAX), 1);
        assert_eq!(lt_word(1u64 << 63, (1u64 << 63) - 1), 0);
        assert_eq!(lt_word((1u64 << 63) - 1, 1u64 << 63), 1);
    }

    #[test]
    fn test_select_word() {
        assert_eq!(select_word(3u8, 7u8, 0), 3);
        assert_eq!(select_word(3u8, 7u8, 1), 7);
        assert_eq!(select_word(-3i32, 7i32, 1), 7);
        assert_eq!(select_word(-3i32, 7i32, 0), -3);
    }

    #[test]
    fn test_eq_limbs() {
        assert_eq!(eq_limbs(&[1u64, 2, 3], &[1, 2, 3]), 1);
        assert_eq!(eq_limbs(&[1u64, 2, 3], &[1, 2, 4]), 0);
        assert_eq!(eq_limbs(&[1u64, 2, 3], &[1, 2]), 0);
        assert_eq!(eq_limbs::<u8>(&[], &[]), 1);
        assert_eq!(eq_limbs(&[-1i32, 0], &[-1, 0]), 1);
    }

    #[test]
    fn test_is_zero_limbs() {
        assert_eq!(is_zero_limbs(&[0u32; 4]), 1);
        assert_eq!(is_zero_limbs::<u32>(&[]), 1);
        assert_eq!(is_zero_limbs(&[0u32, 0, 0, 1]), 0);
        assert_eq!(is_zero_limbs(&[0i32, -1]), 0);
    }

    #[test]
    fn test_lt_limbs() {
        assert_eq!(lt_limbs(&[0u8, 0, 0, 0], &[0, 0, 0, 1]), 1);
        assert_eq!(lt_limbs(&[0u8, 0, 0, 1], &[0, 0, 0, 0]), 0);
        assert_eq!(lt_limbs(&[0u8, 0, 0, 1], &[0, 0, 0, 1]), 0);
        assert_eq!(lt_limbs(&[255u8, 0, 0, 0], &[255, 0, 0, 1]), 1);
        assert_eq!(lt_limbs(&[255u8, 255, 255, 254], &[255, 255, 255, 255]), 1);
        assert_eq!(lt_limbs(&[1u8, 0, 0, 0], &[0, 255, 255, 255]), 0);
        assert_eq!(lt_limbs(&[u64::MAX, 0], &[u64::MAX, 1]), 1);
        assert_eq!(lt_limbs(&[0u64, u64::MAX], &[1, 0]), 1);
    }

    #[test]
    fn test_select_and_swap_limbs() {
        let a = [1u64, 2, 3];
        let b = [4u64, 5, 6];
        assert_eq!(select_limbs(&a, &b, 0), a);
        assert_eq!(select_limbs(&a, &b, 1), b);
        let (mut x, mut y) = (a, b);
        swap_limbs(&mut x, &mut y, 0);
        assert_eq!((x, y), (a, b));
        swap_limbs(&mut x, &mut y, 1);
        assert_eq!((x, y), (b, a));
        let (mut p, mut q) = ([-1i32, 2], [3i32, -4]);
        swap_limbs(&mut p, &mut q, 1);
        assert_eq!((p, q), ([3, -4], [-1, 2]));
    }

    #[test]
    fn test_abs_i8() {
        assert_eq!(abs_i8(0), (0, 0));
        assert_eq!(abs_i8(7), (7, 0));
        assert_eq!(abs_i8(-7), (7, 1));
        assert_eq!(abs_i8(-8), (8, 1));
        assert_eq!(abs_i8(8), (8, 0));
    }
}
