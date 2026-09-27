use crate::utils::Choice;

pub fn less_than(a: &[u8], b: &[u8]) -> Choice {
    let mut borrow = 0u16;
    for (&a, &b) in a.iter().zip(b).rev() {
        let carry = u16::from(b).wrapping_add(borrow >> 7);
        borrow = u16::from(a).wrapping_sub(carry) >> 8;
    }
    Choice::nonzero(borrow)
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
            assert!(!less_than(&x, &x).to_bool());
        }
        assert!(less_than(&A, &B).to_bool());
        assert!(less_than(&A, &C).to_bool());
        assert!(less_than(&B, &C).to_bool());
        assert!(less_than(&B, &D).to_bool());
        assert!(less_than(&C, &D).to_bool());
        assert!(less_than(&C, &E).to_bool());
        assert!(less_than(&E, &F).to_bool());
        assert!(!less_than(&B, &A).to_bool());
        assert!(!less_than(&C, &A).to_bool());
        assert!(!less_than(&D, &B).to_bool());
        assert!(!less_than(&F, &E).to_bool());
    }
}
