pub fn xor(x: &mut [u8], y: &[u8]) {
    for (a, b) in x.iter_mut().zip(y) {
        *a ^= b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let mut x = [0, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216];
        let y = [0, 129, 129, 138, 254, 243, 236, 227, 82, 207, 10, 195];
        let z = [0, 59, 217, 196, 115, 132, 29, 219, 205, 233, 134, 27];
        xor(&mut x, &y);
        assert_eq!(x, z);
    }

    #[test]
    fn test_xor_different_sizes() {
        let mut x = [0, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216];
        let y = [0, 129, 129, 138, 254, 243, 236, 227];
        let z = [0, 59, 217, 196, 115, 132, 29, 219, 159, 38, 140, 216];
        xor(&mut x, &y);
        assert_eq!(x, z);
    }
}
