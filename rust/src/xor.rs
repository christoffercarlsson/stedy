use alloc::{vec, vec::Vec};

fn calculate(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| *x ^ *y).collect()
}

#[allow(clippy::comparison_chain)]
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    let a_size = a.len();
    let b_size = b.len();
    if a_size > b_size {
        let mut padded = vec![0; a_size - b_size];
        padded.extend_from_slice(b);
        calculate(a, &padded)
    } else if b_size > a_size {
        let mut padded = vec![0; b_size - a_size];
        padded.extend_from_slice(a);
        calculate(&padded, b)
    } else {
        calculate(a, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_xor() {
        let a = vec![0, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216];
        let b = vec![0, 129, 129, 138, 254, 243, 236, 227, 82, 207, 10, 195];
        let result = vec![0, 59, 217, 196, 115, 132, 29, 219, 205, 233, 134, 27];
        assert_eq!(xor(&a, &b), result);
        assert_eq!(xor(&b, &a), result);
        assert_eq!(xor(&result, &b), a);
        assert_eq!(xor(&result, &a), b);
    }

    #[test]
    fn test_xor_different_sizes() {
        let a = vec![74, 48, 144, 63, 12, 153];
        let b = vec![0, 72, 36, 54, 102, 75, 228, 139, 34, 254, 249];
        let result = vec![0, 72, 36, 54, 102, 1, 212, 27, 29, 242, 96];
        let padded = vec![0, 0, 0, 0, 0, 74, 48, 144, 63, 12, 153];
        assert_eq!(xor(&a, &b), result);
        assert_eq!(xor(&b, &a), result);
        assert_eq!(xor(&result, &b), padded);
        assert_eq!(xor(&result, &a), b);
    }
}
