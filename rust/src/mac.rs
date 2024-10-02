use blake2::Blake2bMac512;
use blake3::{
    keyed_hash as blake3_keyed_hash, Hash as Blake3Hash, KEY_LEN as BLAKE3_KEY_LEN,
    OUT_LEN as BLAKE3_OUT_LEN,
};
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::Error;

pub const BLAKE2B_MAC_SIZE: usize = 64;
pub const BLAKE3_MAC_SIZE: usize = BLAKE3_OUT_LEN;
pub const HMAC_SHA512_SIZE: usize = 64;

pub type Blake2bMac = [u8; BLAKE2B_MAC_SIZE];
type Blake3Key = [u8; BLAKE3_KEY_LEN];
pub type Blake3Mac = [u8; BLAKE3_MAC_SIZE];
pub type HmacSha512 = [u8; HMAC_SHA512_SIZE];

fn create_blake2b_mac(key: &[u8], message: &[u8]) -> Result<Blake2bMac512, Error> {
    let mut mac = Blake2bMac512::new_from_slice(key).or(Err(Error::InvalidKey))?;
    mac.update(message);
    Ok(mac)
}

pub fn blake2b_mac(key: &[u8], message: &[u8]) -> Result<Blake2bMac, Error> {
    let mac = create_blake2b_mac(key, message)?;
    let mut code = [0; BLAKE2B_MAC_SIZE];
    code.copy_from_slice(mac.finalize().into_bytes().as_slice());
    Ok(code)
}

pub fn blake2b_verify(key: &[u8], message: &[u8], code: &[u8]) -> Result<(), Error> {
    let mac = create_blake2b_mac(key, message)?;
    mac.verify_slice(code).or(Err(Error::VerificationFailed))
}

fn create_blake3_hash(key: &[u8], message: &[u8]) -> Result<Blake3Hash, Error> {
    let key: Blake3Key = key.try_into().or(Err(Error::InvalidKey))?;
    Ok(blake3_keyed_hash(&key, message))
}

pub fn blake3_mac(key: &[u8], message: &[u8]) -> Result<Blake3Mac, Error> {
    let hash = create_blake3_hash(key, message)?;
    let mut code = [0; BLAKE3_MAC_SIZE];
    code.copy_from_slice(hash.as_bytes());
    Ok(code)
}

pub fn blake3_verify(key: &[u8], message: &[u8], code: &[u8]) -> Result<(), Error> {
    let a = create_blake3_hash(key, message)?;
    let code: Blake3Mac = code.try_into().or(Err(Error::VerificationFailed))?;
    let b = Blake3Hash::from_bytes(code);
    if a == b {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}

fn create_hmac_sha512(key: &[u8], message: &[u8]) -> Result<Hmac<Sha512>, Error> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).or(Err(Error::InvalidKey))?;
    mac.update(message);
    Ok(mac)
}

pub fn hmac_sha512(key: &[u8], message: &[u8]) -> Result<HmacSha512, Error> {
    let mac = create_hmac_sha512(key, message)?;
    let mut code = [0; HMAC_SHA512_SIZE];
    code.copy_from_slice(mac.finalize().into_bytes().as_slice());
    Ok(code)
}

pub fn hmac_sha512_verify(key: &[u8], message: &[u8], code: &[u8]) -> Result<(), Error> {
    let mac = create_hmac_sha512(key, message)?;
    mac.verify_slice(code).or(Err(Error::VerificationFailed))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_blake2b_mac() {
        let key = b"correct-horse-battery-staple";
        let message = b"Hello World";
        let code: Blake2bMac = [
            132, 170, 219, 83, 173, 92, 101, 237, 23, 239, 83, 60, 207, 44, 100, 4, 126, 215, 222,
            216, 100, 209, 255, 180, 75, 229, 12, 42, 37, 120, 21, 223, 180, 34, 8, 109, 223, 63,
            207, 239, 180, 233, 76, 46, 176, 170, 136, 172, 241, 111, 67, 181, 129, 17, 122, 70,
            173, 209, 50, 157, 240, 77, 39, 107,
        ];
        assert_eq!(blake2b_mac(key, message).unwrap(), code);
        blake2b_verify(key, message, &code).unwrap();
    }

    #[test]
    fn test_blake3_mac() {
        let key = vec![
            26, 238, 43, 197, 126, 12, 144, 121, 72, 98, 60, 82, 37, 141, 156, 180, 16, 56, 59,
            248, 229, 117, 59, 244, 21, 85, 199, 32, 5, 49, 176, 233,
        ];
        let message = b"Hello World";
        let code: Blake3Mac = [
            127, 74, 242, 67, 77, 41, 128, 123, 216, 123, 10, 249, 153, 8, 235, 114, 216, 17, 22,
            58, 182, 68, 79, 137, 29, 100, 7, 52, 164, 5, 133, 154,
        ];
        assert_eq!(blake3_mac(&key, message).unwrap(), code);
        blake3_verify(&key, message, &code).unwrap();
    }

    #[test]
    fn test_hmac_sha512() {
        let key = b"correct-horse-battery-staple";
        let message = b"Hello World";
        let code: HmacSha512 = [
            113, 148, 252, 47, 223, 231, 225, 81, 179, 104, 173, 251, 5, 38, 187, 165, 44, 57, 8,
            113, 52, 139, 46, 152, 4, 7, 202, 138, 210, 13, 250, 202, 231, 156, 153, 82, 69, 74,
            129, 66, 47, 155, 152, 175, 115, 116, 88, 171, 51, 126, 233, 179, 190, 101, 255, 149,
            5, 135, 168, 2, 42, 3, 53, 83,
        ];
        assert_eq!(hmac_sha512(key, message).unwrap(), code);
        hmac_sha512_verify(key, message, &code).unwrap();
    }
}
