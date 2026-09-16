use crate::utils::is_zero_limbs;

#[inline(never)]
pub fn is_zero(a: &[u8]) -> u64 {
    is_zero_limbs(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_zero() {
        assert_eq!(is_zero(&[0; 16]), 1);
        assert_eq!(is_zero(&[]), 1);
        assert_eq!(is_zero(&[1; 16]), 0);
        assert_eq!(is_zero(&[0, 0, 0, 1]), 0);
        assert_eq!(is_zero(&[1, 0, 0, 0]), 0);
    }
}
