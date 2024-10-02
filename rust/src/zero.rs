use zeroize::Zeroize;

pub fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&byte| byte == 0)
}

pub fn zeroize(bytes: &mut [u8]) {
    bytes.zeroize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_is_zero() {
        let mut bytes = vec![0; 8];
        assert!(is_zero(&bytes));
        bytes.insert(0, 1);
        assert!(!is_zero(&bytes));
    }

    #[test]
    fn test_zeroize() {
        let mut bytes = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let zeroes = vec![0; 8];
        zeroize(&mut bytes);
        assert_eq!(bytes, zeroes);
    }
}
