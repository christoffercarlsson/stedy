use crate::{
    chacha20poly1305::{xchacha20poly1305_decrypt, xchacha20poly1305_encrypt},
    rng::Rng,
    x25519::{derive_secret_key, key_pair_from_rng, x25519_generate_key_pair},
};

pub fn cryptobox_key_pair(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    x25519_generate_key_pair(seed)
}

pub fn cryptobox_seal(
    seed: [u8; 32],
    private_key: &[u8; 32],
    public_key: &[u8; 32],
    aad: Option<&[u8]>,
    plaintext: &[u8],
    message: &mut [u8],
) {
    let mut rng = Rng::from(seed);
    seal(&mut rng, private_key, public_key, aad, plaintext, message);
}

fn seal(
    rng: &mut Rng,
    private_key: &[u8; 32],
    public_key: &[u8; 32],
    aad: Option<&[u8]>,
    plaintext: &[u8],
    message: &mut [u8],
) {
    let tag_offset = 24 + plaintext.len();
    let key = derive_secret_key(private_key, public_key);
    let nonce = generate_nonce(rng);
    message[..24].copy_from_slice(&nonce);
    message[24..tag_offset].copy_from_slice(plaintext);
    let tag = xchacha20poly1305_encrypt(&key, &nonce, aad, &mut message[24..tag_offset]);
    message[tag_offset..].copy_from_slice(&tag);
}

fn generate_nonce(rng: &mut Rng) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    rng.fill(&mut nonce);
    nonce
}

pub fn cryptobox_seal_anonymous(
    seed: [u8; 32],
    public_key: &[u8; 32],
    aad: Option<&[u8]>,
    plaintext: &[u8],
    message: &mut [u8],
) {
    let mut rng = Rng::from(seed);
    let (ephemeral_private_key, ephemeral_public_key) = key_pair_from_rng(&mut rng);
    seal(
        &mut rng,
        &ephemeral_private_key,
        public_key,
        aad,
        plaintext,
        &mut message[32..],
    );
    message[..32].copy_from_slice(&ephemeral_public_key);
}

pub fn cryptobox_open(
    private_key: &[u8; 32],
    public_key: &[u8; 32],
    aad: Option<&[u8]>,
    message: &[u8],
    plaintext: &mut [u8],
) -> bool {
    let tag_offset = 24 + plaintext.len();
    let key = derive_secret_key(private_key, public_key);
    let mut nonce = [0u8; 24];
    let mut tag = [0u8; 16];
    nonce.copy_from_slice(&message[..24]);
    tag.copy_from_slice(&message[tag_offset..]);
    plaintext.copy_from_slice(&message[24..tag_offset]);
    xchacha20poly1305_decrypt(&key, &nonce, aad, plaintext, &tag)
}

pub fn cryptobox_open_anonymous(
    private_key: &[u8; 32],
    aad: Option<&[u8]>,
    message: &[u8],
    plaintext: &mut [u8],
) -> bool {
    let mut ephemeral_public_key = [0u8; 32];
    ephemeral_public_key.copy_from_slice(&message[..32]);
    cryptobox_open(
        private_key,
        &ephemeral_public_key,
        aad,
        &message[32..],
        plaintext,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cryptobox_seal() {
        let seed = [0u8; 32];
        let private_key = [
            2, 63, 55, 32, 58, 36, 118, 196, 37, 102, 166, 28, 197, 92, 60, 168, 117, 219, 180,
            204, 65, 192, 222, 183, 137, 248, 231, 191, 136, 24, 54, 56,
        ];
        let public_key = [
            197, 196, 174, 222, 16, 240, 125, 197, 81, 174, 105, 40, 19, 24, 55, 147, 187, 204,
            150, 245, 96, 32, 248, 225, 29, 203, 142, 72, 36, 135, 19, 56,
        ];
        let aad = [80, 81, 82, 83, 192, 193, 194, 195, 196, 197, 198, 199];
        let plaintext = [
            76, 97, 100, 105, 101, 115, 32, 97, 110, 100, 32, 71, 101, 110, 116, 108, 101, 109,
            101, 110, 32, 111, 102, 32, 116, 104, 101, 32, 99, 108, 97, 115, 115, 32, 111, 102, 32,
            39, 57, 57, 58, 32, 73, 102, 32, 73, 32, 99, 111, 117, 108, 100, 32, 111, 102, 102,
            101, 114, 32, 121, 111, 117, 32, 111, 110, 108, 121, 32, 111, 110, 101, 32, 116, 105,
            112, 32, 102, 111, 114, 32, 116, 104, 101, 32, 102, 117, 116, 117, 114, 101, 44, 32,
            115, 117, 110, 115, 99, 114, 101, 101, 110, 32, 119, 111, 117, 108, 100, 32, 98, 101,
            32, 105, 116, 46,
        ];
        let mut message = [0u8; 154];
        cryptobox_seal(
            seed,
            &private_key,
            &public_key,
            Some(&aad),
            &plaintext,
            &mut message,
        );
        assert_eq!(
            message,
            [
                118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189,
                210, 25, 184, 160, 141, 237, 26, 38, 125, 116, 97, 10, 49, 255, 134, 230, 118, 82,
                202, 230, 93, 39, 192, 255, 102, 94, 108, 90, 87, 140, 61, 143, 177, 143, 226, 118,
                98, 239, 66, 229, 8, 106, 97, 124, 104, 134, 64, 123, 175, 231, 1, 197, 125, 165,
                63, 208, 1, 22, 74, 28, 59, 24, 236, 236, 124, 141, 220, 254, 19, 254, 130, 81, 18,
                213, 44, 74, 60, 172, 171, 147, 86, 42, 2, 95, 96, 33, 78, 218, 147, 176, 157, 115,
                240, 91, 37, 218, 100, 118, 24, 172, 194, 158, 41, 101, 89, 159, 77, 51, 244, 244,
                223, 216, 0, 155, 39, 186, 60, 14, 26, 181, 55, 99, 78, 85, 55, 128, 79, 0, 84,
                221, 195, 85, 81, 147, 198, 236, 49
            ]
        );
    }

    #[test]
    fn test_cryptobox_open() {
        let private_key = [
            246, 161, 44, 168, 255, 195, 10, 102, 202, 20, 12, 204, 114, 118, 51, 97, 21, 129, 147,
            97, 24, 109, 63, 83, 93, 217, 159, 142, 170, 202, 143, 206,
        ];
        let public_key = [
            213, 59, 159, 234, 29, 212, 213, 112, 219, 227, 129, 128, 118, 124, 35, 100, 86, 202,
            102, 51, 241, 3, 241, 170, 6, 55, 231, 182, 19, 210, 82, 116,
        ];
        let aad = [80, 81, 82, 83, 192, 193, 194, 195, 196, 197, 198, 199];
        let message = [
            118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189, 210,
            25, 184, 160, 141, 237, 26, 38, 125, 116, 97, 10, 49, 255, 134, 230, 118, 82, 202, 230,
            93, 39, 192, 255, 102, 94, 108, 90, 87, 140, 61, 143, 177, 143, 226, 118, 98, 239, 66,
            229, 8, 106, 97, 124, 104, 134, 64, 123, 175, 231, 1, 197, 125, 165, 63, 208, 1, 22,
            74, 28, 59, 24, 236, 236, 124, 141, 220, 254, 19, 254, 130, 81, 18, 213, 44, 74, 60,
            172, 171, 147, 86, 42, 2, 95, 96, 33, 78, 218, 147, 176, 157, 115, 240, 91, 37, 218,
            100, 118, 24, 172, 194, 158, 41, 101, 89, 159, 77, 51, 244, 244, 223, 216, 0, 155, 39,
            186, 60, 14, 26, 181, 55, 99, 78, 85, 55, 128, 79, 0, 84, 221, 195, 85, 81, 147, 198,
            236, 49,
        ];
        let mut plaintext = [0u8; 114];
        let result = cryptobox_open(
            &private_key,
            &public_key,
            Some(&aad),
            &message,
            &mut plaintext,
        );
        assert!(result == true);
        assert_eq!(
            plaintext,
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
    fn test_cryptobox_anonymous() {
        let seed = [1u8; 32];
        let private_key = [
            246, 161, 44, 168, 255, 195, 10, 102, 202, 20, 12, 204, 114, 118, 51, 97, 21, 129, 147,
            97, 24, 109, 63, 83, 93, 217, 159, 142, 170, 202, 143, 206,
        ];
        let public_key = [
            197, 196, 174, 222, 16, 240, 125, 197, 81, 174, 105, 40, 19, 24, 55, 147, 187, 204,
            150, 245, 96, 32, 248, 225, 29, 203, 142, 72, 36, 135, 19, 56,
        ];
        let aad = [80, 81, 82, 83, 192, 193, 194, 195, 196, 197, 198, 199];
        let plaintext = [
            76, 97, 100, 105, 101, 115, 32, 97, 110, 100, 32, 71, 101, 110, 116, 108, 101, 109,
            101, 110, 32, 111, 102, 32, 116, 104, 101, 32, 99, 108, 97, 115, 115, 32, 111, 102, 32,
            39, 57, 57, 58, 32, 73, 102, 32, 73, 32, 99, 111, 117, 108, 100, 32, 111, 102, 102,
            101, 114, 32, 121, 111, 117, 32, 111, 110, 108, 121, 32, 111, 110, 101, 32, 116, 105,
            112, 32, 102, 111, 114, 32, 116, 104, 101, 32, 102, 117, 116, 117, 114, 101, 44, 32,
            115, 117, 110, 115, 99, 114, 101, 101, 110, 32, 119, 111, 117, 108, 100, 32, 98, 101,
            32, 105, 116, 46,
        ];
        let mut message = [0u8; 186];
        cryptobox_seal_anonymous(seed, &public_key, Some(&aad), &plaintext, &mut message);
        assert_eq!(
            message,
            [
                213, 59, 159, 234, 29, 212, 213, 112, 219, 227, 129, 128, 118, 124, 35, 100, 86,
                202, 102, 51, 241, 3, 241, 170, 6, 55, 231, 182, 19, 210, 82, 116, 30, 204, 54,
                134, 182, 14, 227, 184, 75, 108, 125, 50, 29, 112, 213, 192, 110, 157, 172, 99,
                164, 208, 167, 157, 176, 95, 183, 213, 194, 196, 62, 234, 32, 77, 66, 39, 95, 158,
                189, 102, 253, 20, 118, 62, 95, 12, 135, 46, 242, 231, 129, 113, 202, 185, 86, 163,
                181, 215, 170, 16, 214, 147, 146, 177, 183, 39, 119, 63, 68, 62, 167, 238, 67, 128,
                25, 103, 218, 221, 52, 240, 49, 140, 66, 103, 200, 160, 42, 86, 148, 237, 174, 202,
                219, 51, 29, 140, 123, 254, 80, 248, 201, 106, 213, 95, 16, 234, 1, 61, 60, 237, 7,
                96, 148, 80, 24, 65, 225, 239, 17, 116, 253, 15, 64, 179, 144, 210, 105, 39, 210,
                95, 31, 130, 221, 8, 69, 135, 205, 98, 73, 74, 96, 143, 223, 108, 49, 137, 130,
                245, 242, 214, 90, 92, 193, 250
            ]
        );
        let mut decrypted_plaintext = [0u8; 114];
        let result =
            cryptobox_open_anonymous(&private_key, Some(&aad), &message, &mut decrypted_plaintext);
        assert!(result == true);
        assert_eq!(decrypted_plaintext, plaintext);
    }
}
