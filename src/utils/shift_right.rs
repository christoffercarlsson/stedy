pub fn shift_right(bytes: &mut [u8], bits: usize) {
    let mut carry = 0u8;
    for byte in bytes.iter_mut() {
        let value = *byte;
        *byte = (value >> bits) | carry;
        carry = ((value as u16) << (8 - bits)) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shift_right_by_zero() {
        let mut bytes = [18, 52, 86, 120];
        shift_right(&mut bytes, 0);
        assert_eq!(bytes, [18, 52, 86, 120]);
    }

    #[test]
    fn test_shift_right() {
        let mut bytes = [1, 2];
        shift_right(&mut bytes, 7);
        assert_eq!(bytes, [0, 2]);
        let mut bytes = [255, 0];
        shift_right(&mut bytes, 4);
        assert_eq!(bytes, [15, 240]);
        let mut bytes = [128, 1];
        shift_right(&mut bytes, 1);
        assert_eq!(bytes, [64, 0]);
    }
}
