pub fn is_zero(a: &[u8]) -> bool {
    let mut result = 0;
    for &x in a {
        result |= x;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_zero() {
        assert!(is_zero(&[0; 16]));
        assert!(is_zero(&[]));
        assert!(!is_zero(&[1; 16]));
        assert!(!is_zero(&[0, 0, 0, 1]));
        assert!(!is_zero(&[1, 0, 0, 0]));
    }
}
