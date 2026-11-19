use crate::{
    Error,
    traits::{CryptoRng, Sealed},
};

pub struct FixedRng<'a>(&'a [u8]);

impl FixedRng<'_> {
    pub fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        let (head, tail) = self
            .0
            .split_at_checked(bytes.len())
            .ok_or(Error::LimitExceeded)?;
        bytes.copy_from_slice(head);
        self.0 = tail;
        Ok(())
    }
}

impl<'a> From<&'a [u8]> for FixedRng<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}

impl Sealed for FixedRng<'_> {}

impl CryptoRng for FixedRng<'_> {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.fill(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill() {
        let seed = [1, 2, 3, 4, 5];
        let mut rng = FixedRng::from(seed.as_ref());
        let mut output = [0u8; 2];
        rng.fill(&mut output).unwrap();
        assert_eq!(output, [1, 2]);
        rng.fill(&mut output).unwrap();
        assert_eq!(output, [3, 4]);
        assert_eq!(rng.fill(&mut output), Err(Error::LimitExceeded));
        let mut output = [0u8; 1];
        rng.fill(&mut output).unwrap();
        assert_eq!(output, [5]);
        assert_eq!(rng.fill(&mut output), Err(Error::LimitExceeded));
    }
}
