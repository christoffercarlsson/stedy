use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use blake3::Hasher;
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use scrypt::{scrypt as scrypt_kdf, Params as ScryptParams};
use sha2::Sha512;

use crate::Error;

const ARGON2_DEFAULT_ITERATIONS: u32 = 3;
const ARGON2_DEFAULT_MEMORY: u32 = 65536;
const ARGON2_DEFAULT_PARALLELISM: u32 = 2;
const PBKDF2_DEFAULT_ITERATIONS: u32 = 10000;

pub fn argon2d(
    okm: &mut [u8],
    password: &[u8],
    salt: &[u8],
    iterations: Option<u32>,
    memory: Option<u32>,
    parallelism: Option<u32>,
) -> Result<(), Error> {
    let params = ParamsBuilder::new()
        .t_cost(iterations.unwrap_or(ARGON2_DEFAULT_ITERATIONS))
        .m_cost(memory.unwrap_or(ARGON2_DEFAULT_MEMORY))
        .p_cost(parallelism.unwrap_or(ARGON2_DEFAULT_PARALLELISM))
        .build()
        .or(Err(Error::KeyDerivationFailed))?;
    Argon2::new(Algorithm::Argon2d, Version::default(), params)
        .hash_password_into(password, salt, okm)
        .or(Err(Error::KeyDerivationFailed))
}

pub fn blake3_kdf(okm: &mut [u8], ikm: &[u8], context: &str) -> Result<(), Error> {
    let mut hasher = Hasher::new_derive_key(context);
    hasher.update(ikm);
    let mut output_reader = hasher.finalize_xof();
    output_reader.fill(okm);
    Ok(())
}

pub fn hkdf_sha512(
    okm: &mut [u8],
    ikm: &[u8],
    salt: Option<&[u8]>,
    context: Option<&[u8]>,
) -> Result<(), Error> {
    let h = Hkdf::<Sha512>::new(salt, ikm);
    match h.expand(context.unwrap_or(&[]), okm) {
        Ok(_) => Ok(()),
        Err(_) => Err(Error::KeyDerivationFailed),
    }
}

pub fn pbkdf2_sha512(
    okm: &mut [u8],
    password: &[u8],
    salt: &[u8],
    iterations: Option<u32>,
) -> Result<(), Error> {
    pbkdf2_hmac::<Sha512>(
        password,
        salt,
        iterations.unwrap_or(PBKDF2_DEFAULT_ITERATIONS),
        okm,
    );
    Ok(())
}

pub fn scrypt(
    okm: &mut [u8],
    password: &[u8],
    salt: &[u8],
    iterations: Option<u8>,
    block_size: Option<u32>,
    parallelism: Option<u32>,
) -> Result<(), Error> {
    let params = ScryptParams::new(
        iterations.unwrap_or(ScryptParams::RECOMMENDED_LOG_N),
        block_size.unwrap_or(ScryptParams::RECOMMENDED_R),
        parallelism.unwrap_or(ScryptParams::RECOMMENDED_P),
        okm.len(),
    )
    .or(Err(Error::KeyDerivationFailed))?;
    scrypt_kdf(password, salt, &params, okm).or(Err(Error::KeyDerivationFailed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_argon2d() {
        let mut okm = vec![0; 32];
        let password = b"correct-horse-battery-staple";
        let salt = vec![
            10, 77, 85, 168, 215, 120, 229, 2, 47, 171, 112, 25, 119, 197, 216, 64,
        ];
        let output = vec![
            26, 238, 43, 197, 126, 12, 144, 121, 72, 98, 60, 82, 37, 141, 156, 180, 16, 56, 59,
            248, 229, 117, 59, 244, 21, 85, 199, 32, 5, 49, 176, 233,
        ];
        argon2d(&mut okm, password, &salt, Some(2), Some(4096), Some(8)).unwrap();
        assert_eq!(okm, output);
    }

    #[test]
    fn test_blake3_kdf() {
        let mut okm = vec![0; 42];
        let ikm = vec![
            255, 32, 1, 136, 81, 72, 28, 37, 191, 194, 229, 208, 193, 225, 250, 87, 218, 194, 162,
            55, 161, 169, 97, 146, 249, 154, 16, 218, 71, 170, 84, 66,
        ];
        let context = "Hello World";
        let output = vec![
            210, 200, 199, 111, 188, 69, 227, 242, 165, 62, 44, 145, 89, 247, 49, 236, 131, 54,
            186, 29, 248, 229, 53, 94, 167, 15, 115, 96, 233, 30, 147, 204, 214, 226, 138, 107, 44,
            180, 241, 215, 204, 91,
        ];
        blake3_kdf(&mut okm, &ikm, context).unwrap();
        assert_eq!(okm, output);
    }

    #[test]
    fn test_hkdf_sha512() {
        let mut okm = vec![0; 42];
        let ikm = vec![
            255, 32, 1, 136, 81, 72, 28, 37, 191, 194, 229, 208, 193, 225, 250, 87, 218, 194, 162,
            55, 161, 169, 97, 146, 249, 154, 16, 218, 71, 170, 84, 66,
        ];
        let salt = vec![
            10, 77, 85, 168, 215, 120, 229, 2, 47, 171, 112, 25, 119, 197, 216, 64,
        ];
        let context = vec![
            228, 136, 13, 34, 124, 172, 25, 5, 157, 206, 80, 62, 25, 49, 26, 252, 79, 65, 97, 162,
        ];
        let output = vec![
            167, 160, 194, 242, 26, 110, 17, 188, 48, 14, 165, 137, 82, 23, 135, 193, 226, 170,
            147, 7, 93, 107, 129, 54, 136, 233, 173, 105, 190, 139, 182, 111, 26, 88, 192, 215,
            157, 73, 161, 134, 235, 82,
        ];
        hkdf_sha512(&mut okm, &ikm, Some(&salt), Some(&context)).unwrap();
        assert_eq!(okm, output);
    }

    #[test]
    fn test_pbkdf2() {
        let mut okm = vec![0; 32];
        let password = b"correct-horse-battery-staple";
        let salt = vec![
            10, 77, 85, 168, 215, 120, 229, 2, 47, 171, 112, 25, 119, 197, 216, 64,
        ];
        let output = vec![
            252, 224, 173, 41, 195, 198, 202, 67, 158, 83, 13, 246, 0, 215, 44, 60, 233, 204, 65,
            38, 92, 113, 177, 82, 247, 151, 144, 136, 174, 121, 148, 60,
        ];
        pbkdf2_sha512(&mut okm, password, &salt, Some(42)).unwrap();
        assert_eq!(okm, output);
    }

    #[test]
    fn test_scrypt() {
        let mut okm = vec![0; 32];
        let password = b"correct-horse-battery-staple";
        let salt = vec![
            10, 77, 85, 168, 215, 120, 229, 2, 47, 171, 112, 25, 119, 197, 216, 64,
        ];
        let output = vec![
            188, 176, 105, 19, 54, 218, 22, 200, 126, 52, 243, 90, 165, 162, 246, 24, 85, 112, 43,
            184, 0, 135, 19, 155, 52, 69, 253, 104, 136, 244, 34, 228,
        ];
        scrypt(&mut okm, password, &salt, Some(8), None, None).unwrap();
        assert_eq!(okm, output);
    }
}
