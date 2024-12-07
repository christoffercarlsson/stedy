use crate::Error;

pub fn verify(a: &[u8], b: &[u8]) -> Result<(), Error> {
    if a.len() != b.len() {
        return Err(Error::Verification);
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    if result == 0 {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}
