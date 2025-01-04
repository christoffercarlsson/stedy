use crate::Error;

pub fn verify(a: &[u8], b: &[u8]) -> Result<(), Error> {
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    if result == 0 {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify() {
        let a = [0; 16];
        let b = [0; 16];
        let c = [1; 16];
        assert!(verify(&a, &b).is_ok());
        assert!(verify(&a, &c).is_err());
    }
}
