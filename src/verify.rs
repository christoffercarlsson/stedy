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
