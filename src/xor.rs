pub fn xor(a: &[u8], b: &[u8], c: &mut [u8]) {
    for ((x, y), z) in a.iter().zip(b).zip(c) {
        *z = x ^ y;
    }
}

pub fn xor_mut(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let a = [0, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216];
        let b = [0, 129, 129, 138, 254, 243, 236, 227, 82, 207, 10, 195];
        let c = [0, 59, 217, 196, 115, 132, 29, 219, 205, 233, 134, 27];
        let mut t = [0; 12];
        xor(&a, &b, &mut t);
        assert_eq!(t, c);
        xor(&c, &b, &mut t);
        assert_eq!(t, a);
        xor(&c, &a, &mut t);
        assert_eq!(t, b);
    }

    #[test]
    fn test_xor_mut() {
        let mut a = [0, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216];
        let b = [0, 129, 129, 138, 254, 243, 236, 227, 82, 207, 10, 195];
        let c = [0, 59, 217, 196, 115, 132, 29, 219, 205, 233, 134, 27];
        xor_mut(&mut a, &b);
        assert_eq!(a, c);
    }
}
