use crate::{
    ciphers::aes,
    traits::{CryptoRng, Digest, KeyInit, Mac},
    utils::{increment, verify, wipe, Block, Secret},
    Error,
};

pub type Aegis128L = Aegis<16, 8, 32, 32>;
pub type Aegis256 = Aegis<32, 6, 16, 32>;

#[cfg(feature = "hazmat")]
pub type Aegis128LTag128 = Aegis<16, 8, 32, 16>;
#[cfg(feature = "hazmat")]
pub type Aegis256Tag128 = Aegis<32, 6, 16, 16>;

#[derive(Clone)]
pub struct Aegis<
    const KEY_SIZE: usize,
    const STATE_SIZE: usize,
    const RATE: usize,
    const TAG_SIZE: usize,
> {
    state: Secret<[[u8; 16]; STATE_SIZE]>,
    block: Block<RATE>,
    length: u64,
}

macro_rules! impl_aegis {
    (
        $(#[$attribute:meta])*
        $key_size:literal,
        $state_size:literal,
        $rate:literal,
        $tag_size:literal,
        $encrypt:ident,
        $decrypt:ident
    ) => {
        $(#[$attribute])*
        impl Aegis<$key_size, $state_size, $rate, $tag_size> {
            pub const fn is_accelerated() -> bool {
                aes::is_accelerated()
            }

            pub fn encrypt(
                key: &[u8; $key_size],
                nonce: &[u8; $key_size],
                aad: Option<&[u8]>,
                message: &mut [u8],
            ) -> Result<[u8; $tag_size], Error> {
                Ok(aes::$encrypt::<$tag_size>(
                    key,
                    nonce,
                    aad.unwrap_or_default(),
                    message,
                ))
            }

            pub fn decrypt(
                key: &[u8; $key_size],
                nonce: &[u8; $key_size],
                aad: Option<&[u8]>,
                message: &mut [u8],
                tag: &[u8; $tag_size],
            ) -> Result<(), Error> {
                let expected =
                    aes::$decrypt::<$tag_size>(key, nonce, aad.unwrap_or_default(), message);
                if !verify(&expected, tag) {
                    wipe(message);
                    return Err(Error::Decryption);
                }
                Ok(())
            }

            pub fn generate_key(rng: &mut impl CryptoRng) -> Result<[u8; $key_size], Error> {
                let mut key = [0u8; $key_size];
                rng.fill(&mut key)?;
                Ok(key)
            }

            pub fn increment_nonce(nonce: &mut [u8; $key_size]) -> Result<(), Error> {
                increment(nonce)
            }
        }
    };
}

macro_rules! impl_aegis_mac {
    ($key_size:literal, $state_size:literal, $rate:literal, $init:ident, $absorb:ident, $finalize:ident) => {
        impl Aegis<$key_size, $state_size, $rate, 32> {
            pub fn new(key: &[u8; $key_size], nonce: &[u8; $key_size]) -> Self {
                let mut state = Secret::from([[0u8; 16]; $state_size]);
                aes::$init(key, nonce, state.get_mut());
                Self {
                    state,
                    block: Block::<$rate>::new(),
                    length: 0,
                }
            }

            pub fn update(&mut self, data: &[u8]) {
                self.length += data.len() as u64;
                if let Some((head, tail)) = self.block.blocks(data) {
                    aes::$absorb(self.state.get_mut(), &[head]);
                    aes::$absorb(self.state.get_mut(), tail.as_chunks());
                }
            }

            pub fn finalize_into(mut self, tag: &mut [u8]) {
                if let Some((block, _)) = self.block.remaining_block() {
                    aes::$absorb(self.state.get_mut(), &[block]);
                }
                let computed = aes::$finalize(self.state.get_mut(), self.length);
                let size = tag.len().min(32);
                tag[..size].copy_from_slice(&computed[..size]);
            }

            pub fn finalize(self) -> [u8; 32] {
                let mut tag = [0u8; 32];
                self.finalize_into(&mut tag);
                tag
            }

            pub fn verify(self, tag: &[u8; 32]) -> Result<(), Error> {
                if verify(&self.finalize(), tag) {
                    Ok(())
                } else {
                    Err(Error::Verification)
                }
            }
        }

        impl KeyInit for Aegis<$key_size, $state_size, $rate, 32> {
            fn new(key: &[u8]) -> Result<Self, Error> {
                let (key, nonce) = key.split_at_checked($key_size).ok_or(Error::InvalidKey)?;
                let key = key.try_into().map_err(|_| Error::InvalidKey)?;
                let nonce = nonce.try_into().map_err(|_| Error::InvalidKey)?;
                Ok(Self::new(key, nonce))
            }
        }

        impl Digest for Aegis<$key_size, $state_size, $rate, 32> {
            const OUTPUT_SIZE: usize = 32;

            type Output = [u8; 32];

            fn update(&mut self, message: &[u8]) {
                self.update(message);
            }

            fn finalize(self) -> Self::Output {
                self.finalize()
            }

            fn finalize_into(self, output: &mut [u8]) {
                self.finalize_into(output);
            }
        }

        impl Mac for Aegis<$key_size, $state_size, $rate, 32> {
            fn verify(self, code: &Self::Output) -> Result<(), Error> {
                self.verify(code)
            }
        }
    };
}

impl_aegis!(16, 8, 32, 32, aegis128l_encrypt, aegis128l_decrypt);
impl_aegis!(32, 6, 16, 32, aegis256_encrypt, aegis256_decrypt);

impl_aegis!(
    #[cfg(feature = "hazmat")]
    16,
    8,
    32,
    16,
    aegis128l_encrypt,
    aegis128l_decrypt
);
impl_aegis!(
    #[cfg(feature = "hazmat")]
    32,
    6,
    16,
    16,
    aegis256_encrypt,
    aegis256_decrypt
);

impl_aegis_mac!(
    16,
    8,
    32,
    aegis128l_mac_init,
    aegis128l_mac_absorb,
    aegis128l_mac_finalize
);
impl_aegis_mac!(
    32,
    6,
    16,
    aegis256_mac_init,
    aegis256_mac_absorb,
    aegis256_mac_finalize
);

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-18#appendix-A.2

    #[test]
    fn test_aegis128l_tc1() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let mut message = hex!("00000000000000000000000000000000");
        let tag = Aegis128L::encrypt(&key, &nonce, None, &mut message).unwrap();
        assert_eq!(message, hex!("c1c0e58bd913006feba00f4b3cc3594e"));
        assert_eq!(
            tag,
            hex!("25835bfbb21632176cf03840687cb968cace4617af1bd0f7d064c639a5c79ee4")
        );
        let verified = Aegis128L::decrypt(&key, &nonce, None, &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(message, hex!("00000000000000000000000000000000"));
    }

    #[test]
    fn test_aegis128l_tc2() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let mut message = [0u8; 0];
        let tag = Aegis128L::encrypt(&key, &nonce, None, &mut message).unwrap();
        assert_eq!(
            tag,
            hex!("1360dc9db8ae42455f6e5b6a9d488ea4f2184c4e12120249335c4ee84bafe25d")
        );
        let verified = Aegis128L::decrypt(&key, &nonce, None, &mut message, &tag);
        assert_eq!(verified, Ok(()));
    }

    #[test]
    fn test_aegis128l_tc3() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let tag = Aegis128L::encrypt(&key, &nonce, Some(&aad), &mut message).unwrap();
        assert_eq!(
            message,
            hex!("79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84")
        );
        assert_eq!(
            tag,
            hex!("022cb796fe7e0ae1197525ff67e309484cfbab6528ddef89f17d74ef8ecd82b3")
        );
        let verified = Aegis128L::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(
            message,
            hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        );
    }

    #[test]
    fn test_aegis128l_tc4() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("000102030405060708090a0b0c0d");
        let tag = Aegis128L::encrypt(&key, &nonce, Some(&aad), &mut message).unwrap();
        assert_eq!(message, hex!("79d94593d8c2119d7e8fd9b8fc77"));
        assert_eq!(
            tag,
            hex!("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac")
        );
        let verified = Aegis128L::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(message, hex!("000102030405060708090a0b0c0d"));
    }

    #[test]
    fn test_aegis128l_tc5() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let aad = hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"
        );
        let mut message = hex!(
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
        );
        let tag = Aegis128L::encrypt(&key, &nonce, Some(&aad), &mut message).unwrap();
        assert_eq!(
            message,
            hex!(
                "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10"
            )
        );
        assert_eq!(
            tag,
            hex!("b91e2947a33da8bee89b6794e647baf0fc835ff574aca3fc27c33be0db2aff98")
        );
        let verified = Aegis128L::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(
            message,
            hex!(
                "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
            )
        );
    }

    #[test]
    fn test_aegis128l_tc6() {
        let key = hex!("10000200000000000000000000000000");
        let nonce = hex!("10010000000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let tag = hex!("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac");
        let verified = Aegis128L::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    #[test]
    fn test_aegis128l_tc7() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("79d94593d8c2119d7e8fd9b8fc78");
        let tag = hex!("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac");
        let verified = Aegis128L::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    #[test]
    fn test_aegis128l_tc8() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let aad = hex!("0001020304050608");
        let mut message = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let tag = hex!("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac");
        let verified = Aegis128L::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    #[test]
    fn test_aegis128l_tc9() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let tag = hex!("86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ad");
        let verified = Aegis128L::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-18#appendix-A.3

    #[test]
    fn test_aegis256_tc1() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let mut message = hex!("00000000000000000000000000000000");
        let tag = Aegis256::encrypt(&key, &nonce, None, &mut message).unwrap();
        assert_eq!(message, hex!("754fc3d8c973246dcc6d741412a4b236"));
        assert_eq!(
            tag,
            hex!("1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13")
        );
        let verified = Aegis256::decrypt(&key, &nonce, None, &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(message, hex!("00000000000000000000000000000000"));
    }

    #[test]
    fn test_aegis256_tc2() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let mut message = [0u8; 0];
        let tag = Aegis256::encrypt(&key, &nonce, None, &mut message).unwrap();
        assert_eq!(
            tag,
            hex!("6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a")
        );
        let verified = Aegis256::decrypt(&key, &nonce, None, &mut message, &tag);
        assert_eq!(verified, Ok(()));
    }

    #[test]
    fn test_aegis256_tc3() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let tag = Aegis256::encrypt(&key, &nonce, Some(&aad), &mut message).unwrap();
        assert_eq!(
            message,
            hex!("f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711")
        );
        assert_eq!(
            tag,
            hex!("b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a")
        );
        let verified = Aegis256::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(
            message,
            hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        );
    }

    #[test]
    fn test_aegis256_tc4() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("000102030405060708090a0b0c0d");
        let tag = Aegis256::encrypt(&key, &nonce, Some(&aad), &mut message).unwrap();
        assert_eq!(message, hex!("f373079ed84b2709faee37358458"));
        assert_eq!(
            tag,
            hex!("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9")
        );
        let verified = Aegis256::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(message, hex!("000102030405060708090a0b0c0d"));
    }

    #[test]
    fn test_aegis256_tc5() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let aad = hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"
        );
        let mut message = hex!(
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
        );
        let tag = Aegis256::encrypt(&key, &nonce, Some(&aad), &mut message).unwrap();
        assert_eq!(
            message,
            hex!(
                "57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67"
            )
        );
        assert_eq!(
            tag,
            hex!("a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734")
        );
        let verified = Aegis256::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(
            message,
            hex!(
                "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
            )
        );
    }

    #[test]
    fn test_aegis256_tc6() {
        let key = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("f373079ed84b2709faee37358458");
        let tag = hex!("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9");
        let verified = Aegis256::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    #[test]
    fn test_aegis256_tc7() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("f373079ed84b2709faee37358459");
        let tag = hex!("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9");
        let verified = Aegis256::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    #[test]
    fn test_aegis256_tc8() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let aad = hex!("0001020304050608");
        let mut message = hex!("f373079ed84b2709faee37358458");
        let tag = hex!("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9");
        let verified = Aegis256::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    #[test]
    fn test_aegis256_tc9() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("f373079ed84b2709faee37358458");
        let tag = hex!("8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2da");
        let verified = Aegis256::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-18#appendix-A.8.1

    #[test]
    fn test_aegis128l_mac() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let data = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122");
        let tag = hex!("9490e7c89d420c9f37417fa625eb38e8cad53c5cbec55285e8499ea48377f2a3");
        let mut mac = Aegis128L::new(&key, &nonce);
        mac.update(&data);
        assert_eq!(mac.finalize(), tag);
        let mut mac = Aegis128L::new(&key, &nonce);
        mac.update(&data);
        mac.verify(&tag).unwrap();
        let mut mac = Aegis128L::new(&key, &nonce);
        mac.update(&data[..1]);
        mac.update(&data[1..30]);
        mac.update(&data[30..]);
        mac.verify(&tag).unwrap();
        let mut mac = Aegis128L::new(&key, &nonce);
        mac.update(&data[..32]);
        mac.update(&data[32..]);
        let mut truncated = [0u8; 16];
        mac.finalize_into(&mut truncated);
        assert_eq!(truncated, tag[..16]);
        let mut mac = Aegis128L::new(&key, &nonce);
        mac.update(&data[..34]);
        assert_eq!(mac.verify(&tag), Err(Error::Verification));
        let mut material = [0u8; 32];
        material[..16].copy_from_slice(&key);
        material[16..].copy_from_slice(&nonce);
        let mut mac = <Aegis128L as KeyInit>::new(&material).unwrap();
        Digest::update(&mut mac, &data);
        Mac::verify(mac, &tag).unwrap();
    }

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-18#appendix-A.8.4

    #[test]
    fn test_aegis256_mac() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let data = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122");
        let tag = hex!("a5c906ede3d69545c11e20afa360b221f936e946ed2dba3d7c75ad6dc2784126");
        let mut mac = Aegis256::new(&key, &nonce);
        mac.update(&data);
        assert_eq!(mac.finalize(), tag);
        let mut mac = Aegis256::new(&key, &nonce);
        for byte in data {
            mac.update(&[byte]);
        }
        mac.verify(&tag).unwrap();
        let mut mac = Aegis256::new(&key, &nonce);
        mac.update(&data[..16]);
        mac.update(&data[16..]);
        mac.verify(&tag).unwrap();
        let mut mac = Aegis256::new(&key, &nonce);
        mac.update(&data);
        mac.update(&[0]);
        assert_eq!(mac.verify(&tag), Err(Error::Verification));
        let mut material = [0u8; 64];
        material[..32].copy_from_slice(&key);
        material[32..].copy_from_slice(&nonce);
        let mut mac = <Aegis256 as KeyInit>::new(&material).unwrap();
        Digest::update(&mut mac, &data);
        assert_eq!(Digest::finalize(mac), tag);
    }

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-18#appendix-A.2 (128-bit tags)

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis128l_tag128_tc1() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let mut message = hex!("00000000000000000000000000000000");
        let tag = Aegis128LTag128::encrypt(&key, &nonce, None, &mut message).unwrap();
        assert_eq!(message, hex!("c1c0e58bd913006feba00f4b3cc3594e"));
        assert_eq!(tag, hex!("abe0ece80c24868a226a35d16bdae37a"));
        let verified = Aegis128LTag128::decrypt(&key, &nonce, None, &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(message, hex!("00000000000000000000000000000000"));
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis128l_tag128_tc2() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let mut message = [0u8; 0];
        let tag = Aegis128LTag128::encrypt(&key, &nonce, None, &mut message).unwrap();
        assert_eq!(tag, hex!("c2b879a67def9d74e6c14f708bbcc9b4"));
        let verified = Aegis128LTag128::decrypt(&key, &nonce, None, &mut message, &tag);
        assert_eq!(verified, Ok(()));
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis128l_tag128_tc3() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let tag = Aegis128LTag128::encrypt(&key, &nonce, Some(&aad), &mut message).unwrap();
        assert_eq!(
            message,
            hex!("79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84")
        );
        assert_eq!(tag, hex!("cc6f3372f6aa1bb82388d695c3962d9a"));
        let verified = Aegis128LTag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(
            message,
            hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        );
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis128l_tag128_tc4() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("000102030405060708090a0b0c0d");
        let tag = Aegis128LTag128::encrypt(&key, &nonce, Some(&aad), &mut message).unwrap();
        assert_eq!(message, hex!("79d94593d8c2119d7e8fd9b8fc77"));
        assert_eq!(tag, hex!("5c04b3dba849b2701effbe32c7f0fab7"));
        let verified = Aegis128LTag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(message, hex!("000102030405060708090a0b0c0d"));
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis128l_tag128_tc5() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let aad = hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"
        );
        let mut message = hex!(
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
        );
        let tag = Aegis128LTag128::encrypt(&key, &nonce, Some(&aad), &mut message).unwrap();
        assert_eq!(
            message,
            hex!(
                "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10"
            )
        );
        assert_eq!(tag, hex!("7542a745733014f9474417b337399507"));
        let verified = Aegis128LTag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(
            message,
            hex!(
                "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
            )
        );
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis128l_tag128_tc6() {
        let key = hex!("10000200000000000000000000000000");
        let nonce = hex!("10010000000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let tag = hex!("5c04b3dba849b2701effbe32c7f0fab7");
        let verified = Aegis128LTag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis128l_tag128_tc7() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("79d94593d8c2119d7e8fd9b8fc78");
        let tag = hex!("5c04b3dba849b2701effbe32c7f0fab7");
        let verified = Aegis128LTag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis128l_tag128_tc8() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let aad = hex!("0001020304050608");
        let mut message = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let tag = hex!("5c04b3dba849b2701effbe32c7f0fab7");
        let verified = Aegis128LTag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis128l_tag128_tc9() {
        let key = hex!("10010000000000000000000000000000");
        let nonce = hex!("10000200000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let tag = hex!("6c04b3dba849b2701effbe32c7f0fab8");
        let verified = Aegis128LTag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-18#appendix-A.3 (128-bit tags)

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis256_tag128_tc1() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let mut message = hex!("00000000000000000000000000000000");
        let tag = Aegis256Tag128::encrypt(&key, &nonce, None, &mut message).unwrap();
        assert_eq!(message, hex!("754fc3d8c973246dcc6d741412a4b236"));
        assert_eq!(tag, hex!("3fe91994768b332ed7f570a19ec5896e"));
        let verified = Aegis256Tag128::decrypt(&key, &nonce, None, &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(message, hex!("00000000000000000000000000000000"));
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis256_tag128_tc2() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let mut message = [0u8; 0];
        let tag = Aegis256Tag128::encrypt(&key, &nonce, None, &mut message).unwrap();
        assert_eq!(tag, hex!("e3def978a0f054afd1e761d7553afba3"));
        let verified = Aegis256Tag128::decrypt(&key, &nonce, None, &mut message, &tag);
        assert_eq!(verified, Ok(()));
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis256_tag128_tc3() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let tag = Aegis256Tag128::encrypt(&key, &nonce, Some(&aad), &mut message).unwrap();
        assert_eq!(
            message,
            hex!("f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711")
        );
        assert_eq!(tag, hex!("8d86f91ee606e9ff26a01b64ccbdd91d"));
        let verified = Aegis256Tag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(
            message,
            hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        );
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis256_tag128_tc4() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("000102030405060708090a0b0c0d");
        let tag = Aegis256Tag128::encrypt(&key, &nonce, Some(&aad), &mut message).unwrap();
        assert_eq!(message, hex!("f373079ed84b2709faee37358458"));
        assert_eq!(tag, hex!("c60b9c2d33ceb058f96e6dd03c215652"));
        let verified = Aegis256Tag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(message, hex!("000102030405060708090a0b0c0d"));
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis256_tag128_tc5() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let aad = hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"
        );
        let mut message = hex!(
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
        );
        let tag = Aegis256Tag128::encrypt(&key, &nonce, Some(&aad), &mut message).unwrap();
        assert_eq!(
            message,
            hex!(
                "57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67"
            )
        );
        assert_eq!(tag, hex!("ab8a7d53fd0e98d727accca94925e128"));
        let verified = Aegis256Tag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Ok(()));
        assert_eq!(
            message,
            hex!(
                "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
            )
        );
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis256_tag128_tc6() {
        let key = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("f373079ed84b2709faee37358458");
        let tag = hex!("c60b9c2d33ceb058f96e6dd03c215652");
        let verified = Aegis256Tag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis256_tag128_tc7() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("f373079ed84b2709faee37358459");
        let tag = hex!("c60b9c2d33ceb058f96e6dd03c215652");
        let verified = Aegis256Tag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis256_tag128_tc8() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let aad = hex!("0001020304050608");
        let mut message = hex!("f373079ed84b2709faee37358458");
        let tag = hex!("c60b9c2d33ceb058f96e6dd03c215652");
        let verified = Aegis256Tag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_aegis256_tag128_tc9() {
        let key = hex!("1001000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("1000020000000000000000000000000000000000000000000000000000000000");
        let aad = hex!("0001020304050607");
        let mut message = hex!("f373079ed84b2709faee37358458");
        let tag = hex!("c60b9c2d33ceb058f96e6dd03c215653");
        let verified = Aegis256Tag128::decrypt(&key, &nonce, Some(&aad), &mut message, &tag);
        assert_eq!(verified, Err(Error::Decryption));
        assert_eq!(message, [0u8; 14]);
    }
}
