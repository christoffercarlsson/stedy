use crate::utils::{Choice, Cmov};

pub fn verify<T>(a: &[T], b: &[T]) -> bool
where
    T: Cmov,
{
    Choice::eq_slice(a, b).to_bool()
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
        assert!(!verify(&a[..15], &b));
        assert!(verify(&[u64::MAX, 1], &[u64::MAX, 1]));
        assert!(!verify(&[u64::MAX, 1], &[u64::MAX, 2]));
        assert!(!verify(&[-1i32], &[1]));
    }
}
