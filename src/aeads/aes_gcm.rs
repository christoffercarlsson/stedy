use crate::{
    aeads::Aead,
    ciphers::{Aes128Ctr, Aes256Ctr, AesCtr},
    macs::GHash,
    traits::SeekableStreamCipher,
};

pub type Aes128Gcm = Aead<Aes128Ctr, GHash>;
pub type Aes256Gcm = Aead<Aes256Ctr, GHash>;

impl<const KEY_SIZE: usize> Aead<AesCtr<KEY_SIZE>, GHash>
where
    AesCtr<KEY_SIZE>: SeekableStreamCipher,
{
    pub fn is_supported() -> bool {
        AesCtr::<KEY_SIZE>::is_supported()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::csprngs::Rng, hex_literal::hex};

    // https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

    #[test]
    fn test_aes128gcm_case1() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let message: &mut [u8] = &mut [];
        let tag = Aes128Gcm::encrypt(&key, &nonce, None, message);
        let decrypted = Aes128Gcm::decrypt(&key, &nonce, None, message, &tag);
        assert!(decrypted);
        assert_eq!(tag, hex!("58e2fccefa7e3061367f1d57a4e7455a"));
    }

    #[test]
    fn test_aes128gcm_case2() {
        let plaintext = [0u8; 16];
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let mut message = plaintext;
        let tag = Aes128Gcm::encrypt(&key, &nonce, None, &mut message);
        assert_eq!(message, hex!("0388dace60b6a392f328c2b971b2fe78"));
        let decrypted = Aes128Gcm::decrypt(&key, &nonce, None, &mut message, &tag);
        assert!(decrypted);
        assert_eq!(message, plaintext);
        assert_eq!(tag, hex!("ab6e47d42cec13bdf53a67b21257bddf"));
    }

    #[test]
    fn test_aes128gcm_case3() {
        let plaintext = hex!("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        let key = hex!("feffe9928665731c6d6a8f9467308308");
        let nonce = hex!("cafebabefacedbaddecaf888");
        let mut message = plaintext;
        let tag = Aes128Gcm::encrypt(&key, &nonce, None, &mut message);
        assert_eq!(message, hex!("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"));
        let decrypted = Aes128Gcm::decrypt(&key, &nonce, None, &mut message, &tag);
        assert!(decrypted);
        assert_eq!(message, plaintext);
        assert_eq!(tag, hex!("4d5c2af327cd64a62cf35abd2ba6fab4"));
    }

    #[test]
    fn test_aes128gcm_case4() {
        let plaintext = hex!("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        let key = hex!("feffe9928665731c6d6a8f9467308308");
        let nonce = hex!("cafebabefacedbaddecaf888");
        let aad = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let mut message = plaintext;
        let tag = Aes128Gcm::encrypt(&key, &nonce, Some(&aad), &mut message);
        assert_eq!(message, hex!("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"));
        let decrypted = Aes128Gcm::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert!(decrypted);
        assert_eq!(message, plaintext);
        assert_eq!(tag, hex!("5bc94fbc3221a5db94fae95ae7121a47"));
    }

    #[test]
    fn test_aes256gcm_case13() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let message: &mut [u8] = &mut [];
        let tag = Aes256Gcm::encrypt(&key, &nonce, None, message);
        let decrypted = Aes256Gcm::decrypt(&key, &nonce, None, message, &tag);
        assert!(decrypted);
        assert_eq!(tag, hex!("530f8afbc74536b9a963b4f1c4cb738b"));
    }

    #[test]
    fn test_aes256gcm_case14() {
        let plaintext = [0u8; 16];
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut message = plaintext;
        let tag = Aes256Gcm::encrypt(&key, &nonce, None, &mut message);
        assert_eq!(message, hex!("cea7403d4d606b6e074ec5d3baf39d18"));
        let decrypted = Aes256Gcm::decrypt(&key, &nonce, None, &mut message, &tag);
        assert!(decrypted);
        assert_eq!(message, plaintext);
        assert_eq!(tag, hex!("d0d1c8a799996bf0265b98b5d48ab919"));
    }

    #[test]
    fn test_aes256gcm_case15() {
        let plaintext = hex!("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        let key = hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = hex!("cafebabefacedbaddecaf888");
        let mut message = plaintext;
        let tag = Aes256Gcm::encrypt(&key, &nonce, None, &mut message);
        assert_eq!(message, hex!("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"));
        let decrypted = Aes256Gcm::decrypt(&key, &nonce, None, &mut message, &tag);
        assert!(decrypted);
        assert_eq!(message, plaintext);
        assert_eq!(tag, hex!("b094dac5d93471bdec1a502270e3cc6c"));
    }

    #[test]
    fn test_aes256gcm_case16() {
        let plaintext = hex!("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        let key = hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = hex!("cafebabefacedbaddecaf888");
        let aad = hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let mut message = plaintext;
        let tag = Aes256Gcm::encrypt(&key, &nonce, Some(&aad), &mut message);
        assert_eq!(message, hex!("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"));
        let decrypted = Aes256Gcm::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert!(decrypted);
        assert_eq!(message, plaintext);
        assert_eq!(tag, hex!("76fc6ece0f4e1768cddf8853bb2d551b"));
    }

    #[test]
    fn test_aes128gcm_generate_key() {
        let mut rng = Rng::from(&[0u8; 128]);
        let key = Aes128Gcm::generate_key(&mut rng);
        assert_eq!(
            key,
            [253, 205, 139, 38, 230, 153, 90, 68, 159, 27, 68, 57, 5, 242, 232, 217]
        );
    }

    #[test]
    fn test_aes256gcm_generate_key() {
        let mut rng = Rng::from(&[0u8; 128]);
        let key = Aes256Gcm::generate_key(&mut rng);
        assert_eq!(
            key,
            [
                253, 205, 139, 38, 230, 153, 90, 68, 159, 27, 68, 57, 5, 242, 232, 217, 162, 213,
                40, 127, 15, 170, 40, 184, 218, 178, 64, 246, 99, 149, 165, 24
            ]
        );
    }

    #[test]
    fn test_aes128gcm_increment_nonce() {
        let mut nonce = [42u8; 12];
        let incremented = Aes128Gcm::increment_nonce(&mut nonce);
        assert!(incremented);
        assert_eq!(nonce, [42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 43]);
        let mut nonce = [255u8; 12];
        let incremented = Aes128Gcm::increment_nonce(&mut nonce);
        assert!(!incremented);
        assert_eq!(nonce, [0u8; 12]);
    }

    #[test]
    fn test_aes256gcm_increment_nonce() {
        let mut nonce = [42u8; 12];
        let incremented = Aes256Gcm::increment_nonce(&mut nonce);
        assert!(incremented);
        assert_eq!(nonce, [42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 43]);
        let mut nonce = [255u8; 12];
        let incremented = Aes256Gcm::increment_nonce(&mut nonce);
        assert!(!incremented);
        assert_eq!(nonce, [0u8; 12]);
    }
}
