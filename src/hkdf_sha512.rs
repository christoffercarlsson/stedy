use crate::{hmac_sha512, HmacSha512};

pub fn hkdf_sha512(ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>, okm: &mut [u8]) {
    let prk = extract(salt, ikm);
    expand(&prk, info, okm)
}

fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 64] {
    hmac_sha512(salt.unwrap_or(&[0u8; 64]), ikm)
}

fn expand(prk: &[u8; 64], info: Option<&[u8]>, okm: &mut [u8]) {
    let info = info.unwrap_or(&[]);
    let mut t = [0u8; 64];
    for (i, chunk) in okm.chunks_mut(64).take(255).enumerate() {
        let mut hmac = HmacSha512::new(prk);
        if i > 0 {
            hmac.update(&t);
        }
        hmac.update(info);
        hmac.update(&[(i + 1) as u8]);
        hmac.finalize_into(&mut t);
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
