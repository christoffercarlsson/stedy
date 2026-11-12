use crate::utils::{Choice, Cmov};

pub fn constant_time_eq<T>(a: &[T], b: &[T]) -> bool
where
    T: Cmov,
{
    Choice::eq_slice(a, b).to_bool()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = [0; 16];
        let b = [0; 16];
        let c = [1; 16];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&b, &c));
        assert!(!constant_time_eq(&a[..15], &b));
        assert!(constant_time_eq(&[u64::MAX, 1], &[u64::MAX, 1]));
        assert!(!constant_time_eq(&[u64::MAX, 1], &[u64::MAX, 2]));
        assert!(!constant_time_eq(&[-1i32], &[1]));
    }
}
