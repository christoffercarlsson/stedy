use crate::{
    hmac::{HmacSha256, HmacSha512},
    traits::Mac,
};
use core::marker::PhantomData;

struct Hkdf<M, const DIGEST_SIZE: usize>
where
    M: Mac<DIGEST_SIZE>,
{
    prk: [u8; DIGEST_SIZE],
    m: PhantomData<M>,
}

impl<M, const DIGEST_SIZE: usize> Hkdf<M, DIGEST_SIZE>
where
    M: Mac<DIGEST_SIZE>,
{
    fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let mut mac = M::new(salt.unwrap_or(&[0u8; DIGEST_SIZE]));
        mac.update(ikm);
        let prk = mac.finalize();
        Self {
            prk,
            m: PhantomData::<M>,
        }
    }

    fn expand(self, info: Option<&[u8]>, okm: &mut [u8]) {
        let info = info.unwrap_or(&[]);
        let mut t = [0u8; DIGEST_SIZE];
        for (i, chunk) in okm.chunks_mut(DIGEST_SIZE).take(255).enumerate() {
            let mut mac = M::new(&self.prk);
            if i > 0 {
                mac.update(&t);
            }
            mac.update(info);
            mac.update(&[(i + 1) as u8]);
            mac.finalize_into(&mut t);
            chunk.copy_from_slice(&t[..chunk.len()]);
        }
    }
}

type HkdfSha256 = Hkdf<HmacSha256, 32>;

pub fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>, okm: &mut [u8]) {
    let hkdf = HkdfSha256::extract(salt, ikm);
    hkdf.expand(info, okm);
}

type HkdfSha512 = Hkdf<HmacSha512, 64>;

pub fn hkdf_sha512(ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>, okm: &mut [u8]) {
    let hkdf = HkdfSha512::extract(salt, ikm);
    hkdf.expand(info, okm);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256() {
        let ikm = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let info = [240, 241, 242, 243, 244, 245, 246, 247, 248, 249];
        let mut okm = [0; 42];
        hkdf_sha256(&ikm, Some(&salt), Some(&info), &mut okm);
        assert_eq!(
            okm,
            [
                60, 178, 95, 37, 250, 172, 213, 122, 144, 67, 79, 100, 208, 54, 47, 42, 45, 45, 10,
                144, 207, 26, 90, 76, 93, 176, 45, 86, 236, 196, 197, 191, 52, 0, 114, 8, 213, 184,
                135, 24, 88, 101,
            ]
        );
    }

    #[test]
    fn test_hkdf_sha256_no_salt() {
        let ikm = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let mut okm = [0; 42];
        hkdf_sha256(&ikm, None, None, &mut okm);
        assert_eq!(
            okm,
            [
                141, 164, 231, 117, 165, 99, 193, 143, 113, 95, 128, 42, 6, 60, 90, 49, 184, 161,
                31, 92, 94, 225, 135, 158, 195, 69, 78, 95, 60, 115, 141, 45, 157, 32, 19, 149,
                250, 164, 182, 26, 150, 200,
            ]
        );
    }

    #[test]
    fn test_hkdf_sha512() {
        let ikm = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let info = [240, 241, 242, 243, 244, 245, 246, 247, 248, 249];
        let mut okm = [0; 42];
        hkdf_sha512(&ikm, Some(&salt), Some(&info), &mut okm);
        assert_eq!(
            okm,
            [
                131, 35, 144, 8, 108, 218, 113, 251, 71, 98, 91, 181, 206, 177, 104, 228, 200, 226,
                106, 26, 22, 237, 52, 217, 252, 127, 233, 44, 20, 129, 87, 147, 56, 218, 54, 44,
                184, 217, 249, 37, 215, 203,
            ]
        );
    }

    #[test]
    fn test_hkdf_sha512_no_salt() {
        let ikm = [
            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        ];
        let mut okm = [0; 42];
        hkdf_sha512(&ikm, None, None, &mut okm);
        assert_eq!(
            okm,
            [
                245, 250, 2, 177, 130, 152, 167, 42, 140, 35, 137, 138, 135, 3, 71, 44, 110, 177,
                121, 220, 32, 76, 3, 66, 92, 151, 14, 59, 22, 75, 249, 15, 255, 34, 208, 72, 54,
                208, 226, 52, 59, 172,
            ]
        );
    }
}
