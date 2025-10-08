use crate::{
    chacha::{ChaCha20, XChaCha20},
    poly1305::Poly1305,
    rng::Rng,
    verify::verify,
};

pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
    message: &mut [u8],
) -> [u8; 16] {
    let mut cipher = ChaCha20::from(key, nonce);
    encrypt(&mut cipher, aad, message)
}

pub fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
    message: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    let mut cipher = ChaCha20::from(key, nonce);
    decrypt(&mut cipher, aad, message, tag)
}

pub fn chacha20poly1305_generate_key(seed: [u8; 32]) -> [u8; 32] {
    let mut rng = Rng::from(seed);
    let mut secret_key = [0u8; 32];
    rng.fill(&mut secret_key);
    secret_key
}

pub fn xchacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: Option<&[u8]>,
    message: &mut [u8],
) -> [u8; 16] {
    let mut cipher = XChaCha20::from(key, nonce);
    encrypt(&mut cipher, aad, message)
}

pub fn xchacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: Option<&[u8]>,
    message: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    let mut cipher = XChaCha20::from(key, nonce);
    decrypt(&mut cipher, aad, message, tag)
}

pub fn xchacha20poly1305_generate_key(seed: [u8; 32]) -> [u8; 32] {
    chacha20poly1305_generate_key(seed)
}

pub fn xchacha20poly1305_generate_nonce(seed: [u8; 32]) -> [u8; 24] {
    let mut rng = Rng::from(seed);
    let mut nonce = [0u8; 24];
    rng.fill(&mut nonce);
    nonce
}

pub fn chacha20poly1305_increment_nonce(nonce: &mut [u8; 12]) -> bool {
    increment_nonce(nonce)
}

pub fn xchacha20poly1305_increment_nonce(nonce: &mut [u8; 24]) -> bool {
    increment_nonce(nonce)
}

fn increment_nonce(nonce: &mut [u8]) -> bool {
    let mut carry: u16 = 1;
    for b in nonce.iter_mut().rev() {
        let sum = (*b as u16) + carry;
        *b = sum as u8;
        carry = sum >> 8;
    }
    carry == 0
}

fn encrypt(cipher: &mut ChaCha20, aad: Option<&[u8]>, message: &mut [u8]) -> [u8; 16] {
    let mac = create_mac(cipher);
    cipher.apply_keystream(message);
    calculate_tag(mac, aad, message)
}

fn decrypt(cipher: &mut ChaCha20, aad: Option<&[u8]>, message: &mut [u8], tag: &[u8; 16]) -> bool {
    let mac = create_mac(cipher);
    let t = calculate_tag(mac, aad, message);
    cipher.apply_keystream(message);
    verify(tag, &t)
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

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#appendix-A.3.1

    #[test]
    fn test_xchacha20poly1305() {
        let key = [
            128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144,
            145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
        ];
        let nonce = [
            64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
            86, 87,
        ];
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
        let tag = xchacha20poly1305_encrypt(&key, &nonce, Some(&aad), &mut message);
        assert_eq!(
            message,
            [
                189, 109, 23, 157, 62, 131, 212, 59, 149, 118, 87, 148, 147, 192, 233, 57, 87, 42,
                23, 0, 37, 43, 250, 204, 190, 210, 144, 44, 33, 57, 108, 187, 115, 28, 127, 27, 11,
                74, 166, 68, 11, 243, 168, 47, 78, 218, 126, 57, 174, 100, 198, 112, 140, 84, 194,
                22, 203, 150, 183, 46, 18, 19, 180, 82, 47, 140, 155, 164, 13, 181, 217, 69, 177,
                27, 105, 185, 130, 193, 187, 158, 63, 63, 172, 43, 195, 105, 72, 143, 118, 178, 56,
                53, 101, 211, 255, 249, 33, 249, 102, 76, 151, 99, 125, 169, 118, 136, 18, 246, 21,
                198, 139, 19, 181, 46
            ]
        );
        assert_eq!(
            tag,
            [192, 135, 89, 36, 193, 199, 152, 121, 71, 222, 175, 216, 120, 10, 207, 73]
        );
        let verified = xchacha20poly1305_decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
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
    fn test_xchacha20poly1305_generate_key() {
        let seed = [0u8; 32];
        let key = xchacha20poly1305_generate_key(seed);
        assert_eq!(
            key,
            [
                118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189,
                210, 25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199,
            ]
        );
    }

    #[test]
    fn test_xchacha20poly1305_generate_nonce() {
        let seed = [0u8; 32];
        let nonce = xchacha20poly1305_generate_nonce(seed);
        assert_eq!(
            nonce,
            [
                118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189,
                210, 25, 184, 160, 141, 237, 26,
            ]
        );
    }

    #[test]
    fn test_chacha20poly1305_increment_nonce() {
        let mut nonce = [42u8; 12];
        let incremented = chacha20poly1305_increment_nonce(&mut nonce);
        assert!(incremented == true);
        assert_eq!(nonce, [42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 43]);
        let mut nonce = [255u8; 12];
        let incremented = chacha20poly1305_increment_nonce(&mut nonce);
        assert!(incremented == false);
        assert_eq!(nonce, [0u8; 12]);
    }

    #[test]
    fn test_xchacha20poly1305_increment_nonce() {
        let mut nonce = [0u8; 24];
        let incremented = xchacha20poly1305_increment_nonce(&mut nonce);
        assert!(incremented == true);
        assert_eq!(
            nonce,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        let mut nonce = [255u8; 24];
        let incremented = xchacha20poly1305_increment_nonce(&mut nonce);
        assert!(incremented == false);
        assert_eq!(nonce, [0u8; 24]);
    }
}
