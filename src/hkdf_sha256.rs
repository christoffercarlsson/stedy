use crate::{hmac_sha256, HmacSha256};

pub fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>, okm: &mut [u8]) {
    let prk = extract(salt, ikm);
    expand(&prk, info, okm)
}

fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt.unwrap_or(&[0u8; 32]), ikm)
}

fn expand(prk: &[u8; 32], info: Option<&[u8]>, okm: &mut [u8]) {
    let info = info.unwrap_or(&[]);
    let mut t = [0u8; 32];
    for (i, chunk) in okm.chunks_mut(32).take(255).enumerate() {
        let mut hmac = HmacSha256::new(prk);
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
}
