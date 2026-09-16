use crate::utils::lt_limbs;

#[inline(never)]
pub fn less_than(a: &[u8], b: &[u8]) -> u64 {
    lt_limbs(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_less_than() {
        const A: [u8; 4] = [0, 0, 0, 0];
        const B: [u8; 4] = [0, 0, 0, 1];
        const C: [u8; 4] = [255, 0, 0, 0];
        const D: [u8; 4] = [255, 0, 0, 1];
        const E: [u8; 4] = [255, 255, 255, 254];
        const F: [u8; 4] = [255, 255, 255, 255];
        for x in [A, B, C, D, E, F] {
            assert_eq!(less_than(&x, &x), 0);
        }
        assert_eq!(less_than(&A, &B), 1);
        assert_eq!(less_than(&A, &C), 1);
        assert_eq!(less_than(&B, &C), 1);
        assert_eq!(less_than(&B, &D), 1);
        assert_eq!(less_than(&C, &D), 1);
        assert_eq!(less_than(&C, &E), 1);
        assert_eq!(less_than(&E, &F), 1);
        assert_eq!(less_than(&B, &A), 0);
        assert_eq!(less_than(&C, &A), 0);
        assert_eq!(less_than(&D, &B), 0);
        assert_eq!(less_than(&F, &E), 0);
    }
}
