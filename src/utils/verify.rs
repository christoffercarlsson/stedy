use crate::utils::eq_limbs;

#[inline(never)]
pub fn verify(a: &[u8], b: &[u8]) -> bool {
    eq_limbs(a, b) == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify() {
        let a = [0; 16];
        let b = [0; 16];
        let c = [1; 16];
        assert!(verify(&a, &b));
        assert!(!verify(&a, &c));
        assert!(!verify(&b, &c));
    }

    #[test]
    fn test_verify_rejects_length_mismatch() {
        assert!(!verify(&[1, 2, 3], &[1, 2, 3, 4]));
        assert!(!verify(&[1, 2, 3, 4], &[1, 2, 3]));
        assert!(!verify(&[], &[0]));
        assert!(!verify(&[0], &[]));
        assert!(verify(&[], &[]));
    }
}
