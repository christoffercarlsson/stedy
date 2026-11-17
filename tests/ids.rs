#[cfg(feature = "aes")]
use stedy::aeads::{Aes128Gcm, Aes256Gcm};
use stedy::{
    aeads::{ChaCha20Poly1305, XChaCha20Poly1305},
    hashes::{
        Blake2b, Blake2b160, Blake2b256, Blake2b384, Blake2b512, Blake2s, Blake2s128, Blake2s160,
        Blake2s224, Blake2s256, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha256, Sha384, Sha512,
    },
    kdfs::Hkdf,
    kems::{MlKem512, MlKem768, MlKem1024, XWing},
    key_exchange::{self, X25519},
    macs::Hmac,
    signatures::{self, Ed25519, MlDsa44, MlDsa65, MlDsa87},
    traits::{Aead, HashFunction, Kdf, Kem, KeyExchange, Mac, SignatureScheme},
};
#[cfg(feature = "hazmat")]
use stedy::{
    hashes::{Sha1, Sha3_224With, Sha3_256With, Sha3_384With, Sha3_512With},
    kems::{MlKem512With, MlKem768With, MlKem1024With, XWingWith},
    key_exchange::{P256With, P384With, P521With, X25519With},
    signatures::{Ed25519With, MlDsa44With, MlDsa65With, MlDsa87With},
    traits::{FieldArithmetic, KeccakPermutation},
};

#[cfg(feature = "hazmat")]
struct Keccak;

#[cfg(feature = "hazmat")]
impl KeccakPermutation for Keccak {
    fn permute(_lanes: &mut [u64; 25]) {
        unreachable!("only the IDs are read");
    }
}

#[cfg(feature = "hazmat")]
struct Field<const N: usize>;

#[cfg(feature = "hazmat")]
impl<const N: usize> FieldArithmetic for Field<N> {
    type Bytes = [u8; N];

    fn add(_a: &Self::Bytes, _b: &Self::Bytes) -> Self::Bytes {
        unreachable!("only the IDs are read");
    }

    fn sub(_a: &Self::Bytes, _b: &Self::Bytes) -> Self::Bytes {
        unreachable!("only the IDs are read");
    }

    fn mul(_a: &Self::Bytes, _b: &Self::Bytes) -> Self::Bytes {
        unreachable!("only the IDs are read");
    }
}

#[cfg(feature = "aes")]
#[test]
fn test_aes_aead_ids() {
    assert_eq!(Aes128Gcm::ID, 0x0101);
    assert_eq!(Aes256Gcm::ID, 0x0102);
}

#[test]
fn test_aead_ids() {
    assert_eq!(ChaCha20Poly1305::ID, 0x0103);
    assert_eq!(XChaCha20Poly1305::ID, 0x0104);
}

#[test]
fn test_kdf_ids() {
    assert_eq!(Hkdf::<Sha256>::ID, 0x0202);
    assert_eq!(Hkdf::<Sha384>::ID, 0x0203);
    assert_eq!(Hkdf::<Sha512>::ID, 0x0204);
    assert_eq!(Hkdf::<Sha3_224>::ID, 0x0205);
    assert_eq!(Hkdf::<Sha3_256>::ID, 0x0206);
    assert_eq!(Hkdf::<Sha3_384>::ID, 0x0207);
    assert_eq!(Hkdf::<Sha3_512>::ID, 0x0208);
    assert_eq!(Hkdf::<Blake2b512>::ID, 0x027f);
    assert_eq!(Hkdf::<Blake2s256>::ID, 0x029f);
}

#[test]
fn test_kem_ids() {
    assert_eq!(MlKem512::ID, 0x0301);
    assert_eq!(MlKem768::ID, 0x0302);
    assert_eq!(MlKem1024::ID, 0x0303);
    assert_eq!(XWing::ID, 0x0304);
}

#[test]
fn test_key_exchange_ids() {
    assert_eq!(X25519::ID, 0x0401);
    assert_eq!(key_exchange::P256::ID, 0x0402);
    assert_eq!(key_exchange::P384::ID, 0x0403);
    assert_eq!(key_exchange::P521::ID, 0x0404);
}

#[test]
fn test_mac_ids() {
    assert_eq!(Hmac::<Sha256>::ID, 0x0502);
    assert_eq!(Hmac::<Sha384>::ID, 0x0503);
    assert_eq!(Hmac::<Sha512>::ID, 0x0504);
    assert_eq!(Hmac::<Sha3_224>::ID, 0x0505);
    assert_eq!(Hmac::<Sha3_256>::ID, 0x0506);
    assert_eq!(Hmac::<Sha3_384>::ID, 0x0507);
    assert_eq!(Hmac::<Sha3_512>::ID, 0x0508);
    assert_eq!(Hmac::<Blake2b512>::ID, 0x057f);
    assert_eq!(Hmac::<Blake2s256>::ID, 0x059f);
}

#[test]
fn test_signature_scheme_ids() {
    assert_eq!(Ed25519::ID, 0x0601);
    assert_eq!(signatures::P256::ID, 0x0602);
    assert_eq!(signatures::P384::ID, 0x0603);
    assert_eq!(signatures::P521::ID, 0x0604);
    assert_eq!(MlDsa44::ID, 0x0605);
    assert_eq!(MlDsa65::ID, 0x0606);
    assert_eq!(MlDsa87::ID, 0x0607);
}

#[test]
fn test_hash_function_ids() {
    assert_eq!(Sha256::ID, 0x0702);
    assert_eq!(Sha384::ID, 0x0703);
    assert_eq!(Sha512::ID, 0x0704);
    assert_eq!(Sha3_224::ID, 0x0705);
    assert_eq!(Sha3_256::ID, 0x0706);
    assert_eq!(Sha3_384::ID, 0x0707);
    assert_eq!(Sha3_512::ID, 0x0708);
    assert_eq!(Blake2b::<1>::ID, 0x0740);
    assert_eq!(Blake2b160::ID, 0x0753);
    assert_eq!(Blake2b256::ID, 0x075f);
    assert_eq!(Blake2b384::ID, 0x076f);
    assert_eq!(Blake2b512::ID, 0x077f);
    assert_eq!(Blake2s::<1>::ID, 0x0780);
    assert_eq!(Blake2s128::ID, 0x078f);
    assert_eq!(Blake2s160::ID, 0x0793);
    assert_eq!(Blake2s224::ID, 0x079b);
    assert_eq!(Blake2s256::ID, 0x079f);
}

#[cfg(feature = "hazmat")]
#[test]
fn test_hazmat_ids() {
    assert_eq!(Hkdf::<Sha1>::ID, 0x0201);
    assert_eq!(Hkdf::<Sha3_256With<Keccak>>::ID, Hkdf::<Sha3_256>::ID);
    assert_eq!(MlKem512With::<Keccak>::ID, MlKem512::ID);
    assert_eq!(MlKem768With::<Keccak>::ID, MlKem768::ID);
    assert_eq!(MlKem1024With::<Keccak>::ID, MlKem1024::ID);
    assert_eq!(XWingWith::<Field<32>, Keccak>::ID, XWing::ID);
    assert_eq!(X25519With::<Field<32>>::ID, X25519::ID);
    assert_eq!(P256With::<Field<32>>::ID, key_exchange::P256::ID);
    assert_eq!(P384With::<Field<48>>::ID, key_exchange::P384::ID);
    assert_eq!(P521With::<Field<66>>::ID, key_exchange::P521::ID);
    assert_eq!(Hmac::<Sha1>::ID, 0x0501);
    assert_eq!(Hmac::<Sha3_256With<Keccak>>::ID, Hmac::<Sha3_256>::ID);
    assert_eq!(Ed25519With::<Field<32>, Sha512>::ID, Ed25519::ID);
    assert_eq!(
        signatures::P256With::<Field<32>, Sha256>::ID,
        signatures::P256::ID
    );
    assert_eq!(
        signatures::P384With::<Field<48>, Sha384>::ID,
        signatures::P384::ID
    );
    assert_eq!(
        signatures::P521With::<Field<66>, Sha512>::ID,
        signatures::P521::ID
    );
    assert_eq!(MlDsa44With::<Keccak>::ID, MlDsa44::ID);
    assert_eq!(MlDsa65With::<Keccak>::ID, MlDsa65::ID);
    assert_eq!(MlDsa87With::<Keccak>::ID, MlDsa87::ID);
    assert_eq!(Sha1::ID, 0x0701);
    assert_eq!(Sha3_224With::<Keccak>::ID, Sha3_224::ID);
    assert_eq!(Sha3_256With::<Keccak>::ID, Sha3_256::ID);
    assert_eq!(Sha3_384With::<Keccak>::ID, Sha3_384::ID);
    assert_eq!(Sha3_512With::<Keccak>::ID, Sha3_512::ID);
}
