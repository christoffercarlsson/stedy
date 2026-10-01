use crate::{
    aeads::Aead,
    ciphers::{ChaCha20, XChaCha20},
    macs::Poly1305,
    traits::CryptoRng,
};

pub type ChaCha20Poly1305 = Aead<ChaCha20, Poly1305>;
pub type XChaCha20Poly1305 = Aead<XChaCha20, Poly1305>;

impl XChaCha20Poly1305 {
    pub fn generate_nonce(rng: &mut impl CryptoRng) -> [u8; 24] {
        let mut nonce = [0u8; 24];
        rng.fill(&mut nonce);
        nonce
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::csprngs::ChaCha20Rng, hex_literal::hex};

    // https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2

    #[test]
    fn test_chacha20poly1305() {
        let key = hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex!("070000004041424344454647");
        let aad = hex!("50515253c0c1c2c3c4c5c6c7");
        let mut message = hex!("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
        let tag = ChaCha20Poly1305::encrypt(&key, &nonce, Some(&aad), &mut message);
        assert_eq!(
            message,
            hex!("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")
        );
        assert_eq!(tag, hex!("1ae10b594f09e26a7e902ecbd0600691"));
        let verified = ChaCha20Poly1305::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert!(verified);
        assert_eq!(
            message,
            hex!("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
        );
    }

    #[test]
    fn test_chacha20poly1305_generate_key() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let key = ChaCha20Poly1305::generate_key(&mut rng);
        assert_eq!(
            key,
            [
                189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102,
                238, 246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 204
            ]
        );
    }

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#appendix-A.3.1

    #[test]
    fn test_xchacha20poly1305() {
        let key = hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex!("404142434445464748494a4b4c4d4e4f5051525354555657");
        let aad = hex!("50515253c0c1c2c3c4c5c6c7");
        let mut message = hex!("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
        let tag = XChaCha20Poly1305::encrypt(&key, &nonce, Some(&aad), &mut message);
        assert_eq!(
            message,
            hex!("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e")
        );
        assert_eq!(tag, hex!("c0875924c1c7987947deafd8780acf49"));
        let verified = XChaCha20Poly1305::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert!(verified);
        assert_eq!(
            message,
            hex!("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
        );
    }

    #[test]
    fn test_xchacha20poly1305_generate_key() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let key = XChaCha20Poly1305::generate_key(&mut rng);
        assert_eq!(
            key,
            [
                189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102,
                238, 246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 204
            ]
        );
    }

    #[test]
    fn test_xchacha20poly1305_generate_nonce() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut rng);
        assert_eq!(
            nonce,
            [
                189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102,
                238, 246, 149, 42, 27, 28, 74
            ]
        );
    }

    #[test]
    fn test_chacha20poly1305_increment_nonce() {
        let mut nonce = [42u8; 12];
        let incremented = ChaCha20Poly1305::increment_nonce(&mut nonce);
        assert!(incremented);
        assert_eq!(nonce, [42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 43]);
        let mut nonce = [255u8; 12];
        let incremented = ChaCha20Poly1305::increment_nonce(&mut nonce);
        assert!(!incremented);
        assert_eq!(nonce, [0u8; 12]);
    }

    #[test]
    fn test_xchacha20poly1305_increment_nonce() {
        let mut nonce = [0u8; 24];
        let incremented = XChaCha20Poly1305::increment_nonce(&mut nonce);
        assert!(incremented);
        assert_eq!(
            nonce,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        let mut nonce = [255u8; 24];
        let incremented = XChaCha20Poly1305::increment_nonce(&mut nonce);
        assert!(!incremented);
        assert_eq!(nonce, [0u8; 24]);
    }
}
