use crate::Error;

pub fn increment(bytes: &mut [u8]) -> Result<(), Error> {
    let mut carry: u16 = 1;
    for b in bytes.iter_mut().rev() {
        let sum = (*b as u16) + carry;
        *b = sum as u8;
        carry = sum >> 8;
    }
    if carry == 0 {
        Ok(())
    } else {
        Err(Error::LimitExceeded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment() {
        let mut bytes = [42, 42, 42, 255];
        assert_eq!(increment(&mut bytes), Ok(()));
        assert_eq!(bytes, [42, 42, 43, 0]);
    }

    #[test]
    fn test_increment_limit() {
        let mut bytes = [255, 255, 255, 255];
        assert_eq!(increment(&mut bytes), Err(Error::LimitExceeded));
        assert_eq!(bytes, [0, 0, 0, 0]);
    }
}
