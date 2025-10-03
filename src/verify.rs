pub fn verify(a: &[u8], b: &[u8]) -> bool {
    let mut result = 0;
    for (x, y) in a.iter().zip(b) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify() {
        let a = [0; 16];
        let b = [0; 16];
        let c = [1; 16];
        assert_eq!(verify(&a, &b), true);
        assert_eq!(verify(&a, &c), false);
    }
}
