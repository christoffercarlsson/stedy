use crate::{chacha::ChaCha20, poly1305::Poly1305, rng::Rng, verify::verify};

pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
    message: &mut [u8],
) -> [u8; 16] {
    let mut cipher = ChaCha20::from(key, nonce);
    let mac = create_mac(&mut cipher);
    encrypt(&mut cipher, message);
    calculate_tag(mac, aad, message)
}

pub fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
    message: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    let mut cipher = ChaCha20::from(key, nonce);
    let mac = create_mac(&mut cipher);
    let t = calculate_tag(mac, aad, message);
    encrypt(&mut cipher, message);
    verify(tag, &t)
}

fn encrypt(cipher: &mut ChaCha20, message: &mut [u8]) {
    cipher.apply_keystream(message);
}

fn create_mac(cipher: &mut ChaCha20) -> Poly1305 {
    let mut key = [0u8; 32];
    cipher.apply_keystream(&mut key);
    Poly1305::new(&key)
}

fn calculate_tag(mut mac: Poly1305, aad: Option<&[u8]>, ciphertext: &[u8]) -> [u8; 16] {
    let aad = aad.unwrap_or(&[]);
    mac.update_padded(aad);
    mac.update_padded(ciphertext);
    mac.update(&(aad.len() as u64).to_le_bytes());
    mac.update(&(ciphertext.len() as u64).to_le_bytes());
    mac.finalize()
}

pub fn chacha20poly1305_generate_key(seed: [u8; 32]) -> [u8; 32] {
    let mut rng = Rng::from(seed);
    let mut secret_key = [0u8; 32];
    rng.fill(&mut secret_key);
    secret_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20poly1305() {
        let key = [
            128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144,
            145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
        ];
        let nonce = [7, 0, 0, 0, 64, 65, 66, 67, 68, 69, 70, 71];
        let aad = [80, 81, 82, 83, 192, 193, 194, 195, 196, 197, 198, 199];
        let mut message = [
            76, 97, 100, 105, 101, 115, 32, 97, 110, 100, 32, 71, 101, 110, 116, 108, 101, 109,
            101, 110, 32, 111, 102, 32, 116, 104, 101, 32, 99, 108, 97, 115, 115, 32, 111, 102, 32,
            39, 57, 57, 58, 32, 73, 102, 32, 73, 32, 99, 111, 117, 108, 100, 32, 111, 102, 102,
            101, 114, 32, 121, 111, 117, 32, 111, 110, 108, 121, 32, 111, 110, 101, 32, 116, 105,
            112, 32, 102, 111, 114, 32, 116, 104, 101, 32, 102, 117, 116, 117, 114, 101, 44, 32,
            115, 117, 110, 115, 99, 114, 101, 101, 110, 32, 119, 111, 117, 108, 100, 32, 98, 101,
            32, 105, 116, 46,
        ];
        let tag = chacha20poly1305_encrypt(&key, &nonce, Some(&aad), &mut message);
        assert_eq!(
            message,
            [
                211, 26, 141, 52, 100, 142, 96, 219, 123, 134, 175, 188, 83, 239, 126, 194, 164,
                173, 237, 81, 41, 110, 8, 254, 169, 226, 181, 167, 54, 238, 98, 214, 61, 190, 164,
                94, 140, 169, 103, 18, 130, 250, 251, 105, 218, 146, 114, 139, 26, 113, 222, 10,
                158, 6, 11, 41, 5, 214, 165, 182, 126, 205, 59, 54, 146, 221, 189, 127, 45, 119,
                139, 140, 152, 3, 174, 227, 40, 9, 27, 88, 250, 179, 36, 228, 250, 214, 117, 148,
                85, 133, 128, 139, 72, 49, 215, 188, 63, 244, 222, 240, 142, 75, 122, 157, 229,
                118, 210, 101, 134, 206, 198, 75, 97, 22
            ]
        );
        assert_eq!(
            tag,
            [26, 225, 11, 89, 79, 9, 226, 106, 126, 144, 46, 203, 208, 96, 6, 145]
        );
        let verified = chacha20poly1305_decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert!(verified);
        assert_eq!(
            message,
            [
                76, 97, 100, 105, 101, 115, 32, 97, 110, 100, 32, 71, 101, 110, 116, 108, 101, 109,
                101, 110, 32, 111, 102, 32, 116, 104, 101, 32, 99, 108, 97, 115, 115, 32, 111, 102,
                32, 39, 57, 57, 58, 32, 73, 102, 32, 73, 32, 99, 111, 117, 108, 100, 32, 111, 102,
                102, 101, 114, 32, 121, 111, 117, 32, 111, 110, 108, 121, 32, 111, 110, 101, 32,
                116, 105, 112, 32, 102, 111, 114, 32, 116, 104, 101, 32, 102, 117, 116, 117, 114,
                101, 44, 32, 115, 117, 110, 115, 99, 114, 101, 101, 110, 32, 119, 111, 117, 108,
                100, 32, 98, 101, 32, 105, 116, 46,
            ]
        );
    }

    #[test]
    fn test_chacha20poly1305_generate_key() {
        let seed = [0u8; 32];
        let key = chacha20poly1305_generate_key(seed);
        assert_eq!(
            key,
            [
                118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189,
                210, 25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199,
            ]
        );
    }
}
