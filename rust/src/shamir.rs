use alloc::vec::Vec;
use shamirsecretsharing::{combine_shares, create_shares, DATA_SIZE, SHARE_SIZE};

use crate::{pad, unpad, Error};

pub const SHAMIR_SECRET_SIZE: usize = DATA_SIZE;
pub const SHAMIR_SHARE_SIZE: usize = SHARE_SIZE;

pub type ShamirShare = [u8; SHAMIR_SHARE_SIZE];
pub type ShamirSecret = [u8; SHAMIR_SECRET_SIZE];

pub fn shamir_split_unpadded(
    secret: &[u8],
    count: u8,
    threshold: u8,
) -> Result<Vec<ShamirShare>, Error> {
    match create_shares(secret, count, threshold) {
        Ok(shares) => shares
            .into_iter()
            .map(|v| v.try_into().or(Err(Error::ConversionFailed)))
            .collect(),
        Err(_) => Err(Error::InvalidInput),
    }
}

pub fn shamir_combine_unpadded(shares: &[ShamirShare]) -> Result<ShamirSecret, Error> {
    let shares: Vec<Vec<u8>> = shares.iter().map(|share| share.to_vec()).collect();
    match combine_shares(&shares) {
        Ok(Some(secret)) => secret.try_into().or(Err(Error::CombinationFailed)),
        _ => Err(Error::CombinationFailed),
    }
}

pub fn shamir_split(secret: &[u8], count: u8, threshold: u8) -> Result<Vec<ShamirShare>, Error> {
    let mut secret = secret.to_vec();
    pad(&mut secret, SHAMIR_SECRET_SIZE);
    shamir_split_unpadded(&secret, count, threshold)
}

pub fn shamir_combine(shares: &[ShamirShare]) -> Result<Vec<u8>, Error> {
    let mut secret = shamir_combine_unpadded(shares)?.to_vec();
    unpad(&mut secret, SHAMIR_SECRET_SIZE)?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_secret_sharing() {
        let secret = b"correct-horse-battery-staple".to_vec();
        let mut shares = shamir_split(&secret, 5, 4).unwrap();
        assert_eq!(shares.len(), 5);
        assert_eq!(shamir_combine(&shares).unwrap(), secret);
        shares.remove(3);
        assert_eq!(shamir_combine(&shares).unwrap(), secret);
        shares.remove(0);
        assert!(shamir_combine(&shares).is_err());
    }
}
