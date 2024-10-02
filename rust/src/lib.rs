#![no_std]

extern crate aes_gcm;
extern crate alloc;
extern crate argon2;
extern crate blake2;
extern crate blake3;
extern crate chacha20poly1305;
extern crate crypto_box as _crypto_box;
extern crate ed25519_dalek;
extern crate hkdf;
extern crate hmac;
#[cfg(feature = "web")]
extern crate js_sys;
extern crate pbkdf2;
extern crate rand_core;
extern crate scrypt;
extern crate sha2;
extern crate shamirsecretsharing;
extern crate x25519_dalek;
extern crate zeroize;

pub use alloc::{vec, vec::Vec};
pub use rand_core::CryptoRngCore;

#[derive(Debug)]
pub enum Error {
    DecodingFailed,
    InvalidPadding,
    InvalidOffset,
    KeyDerivationFailed,
    InvalidKey,
    VerificationFailed,
    SigningFailed,
    EncryptionFailed,
    DecryptionFailed,
    InvalidNonce,
    IncrementFailed,
    ConversionFailed,
    InvalidInput,
    CombinationFailed,
}

#[derive(Debug)]
pub enum Encoding {
    Hex,
    Base16,
    Base32,
    Base32Unpadded,
    Base64,
    Base64Unpadded,
    Base64Url,
    Base64UrlUnpadded,
}

mod aead;
mod base;
mod crypto_box;
mod decode;
mod encode;
mod hash;
mod kdf;
mod key_exchange;
mod key_pair;
mod mac;
mod numbers;
mod pad;
mod random;
mod shamir;
mod sign;
mod transcode;
#[cfg(feature = "web")]
mod web;
mod xor;
mod zero;

pub use aead::{
    aes_256_gcm_decrypt, aes_256_gcm_encrypt, aes_256_gcm_generate_key, aes_256_gcm_generate_nonce,
    chacha20poly1305_decrypt, chacha20poly1305_encrypt, chacha20poly1305_generate_key,
    chacha20poly1305_generate_nonce, Aes256GcmKey, Aes256GcmNonce, ChaCha20Poly1305Key,
    ChaCha20Poly1305Nonce, AES_256_GCM_KEY_SIZE, AES_256_GCM_NONCE_SIZE, AES_256_GCM_TAG_SIZE,
    CHACHA20_POLY1305_KEY_SIZE, CHACHA20_POLY1305_NONCE_SIZE, CHACHA20_POLY1305_TAG_SIZE,
};
pub use crypto_box::{
    x25519_decrypt, x25519_encrypt, x25519_generate_key_pair, x25519_get_private_key,
    x25519_get_public_key, xchacha20poly1305_generate_nonce, X25519KeyPair, X25519PrivateKey,
    X25519PublicKey, XChaCha20Poly1305Nonce, X25519_KEY_PAIR_SIZE, X25519_PRIVATE_KEY_SIZE,
    X25519_PUBLIC_KEY_SIZE, XCHACHA20_POLY1305_NONCE_SIZE,
};
pub use decode::decode;
pub use encode::encode;
pub use hash::{
    blake2b, blake3, sha512, Blake2bDigest, Blake3Digest, Sha512Digest, BLAKE2B_DIGEST_SIZE,
    BLAKE3_DIGEST_SIZE, SHA512_DIGEST_SIZE,
};
pub use kdf::{argon2d, blake3_kdf, hkdf_sha512, pbkdf2_sha512, scrypt};
pub use key_exchange::{x25519_key_exchange, X25519SharedSecret, X25519_SHARED_SECRET_SIZE};
pub use mac::{
    blake2b_mac, blake2b_verify, blake3_mac, blake3_verify, hmac_sha512, hmac_sha512_verify,
    Blake2bMac, Blake3Mac, HmacSha512, BLAKE2B_MAC_SIZE, BLAKE3_MAC_SIZE, HMAC_SHA512_SIZE,
};
pub use numbers::{
    increment_nonce, read_f32_be, read_f32_le, read_f64_be, read_f64_le, read_i128_be,
    read_i128_le, read_i16_be, read_i16_le, read_i32_be, read_i32_le, read_i64_be, read_i64_le,
    read_i8, read_isize_be, read_isize_le, read_nonce, read_u128_be, read_u128_le, read_u16_be,
    read_u16_le, read_u32_be, read_u32_le, read_u64_be, read_u64_le, read_u8, read_usize_be,
    read_usize_le, write_f32_be, write_f32_le, write_f64_be, write_f64_le, write_i128_be,
    write_i128_le, write_i16_be, write_i16_le, write_i32_be, write_i32_le, write_i64_be,
    write_i64_le, write_i8, write_isize_be, write_isize_le, write_u128_be, write_u128_le,
    write_u16_be, write_u16_le, write_u32_be, write_u32_le, write_u64_be, write_u64_le, write_u8,
    write_usize_be, write_usize_le,
};
pub use pad::{pad, unpad};
pub use random::get_random_bytes;
pub use shamir::{
    shamir_combine, shamir_combine_unpadded, shamir_split, shamir_split_unpadded, ShamirSecret,
    ShamirShare, SHAMIR_SECRET_SIZE, SHAMIR_SHARE_SIZE,
};
pub use sign::{
    ed25519_generate_key_pair, ed25519_get_private_key, ed25519_get_public_key, ed25519_sign,
    ed25519_verify, Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
    ED25519_KEY_PAIR_SIZE, ED25519_PRIVATE_KEY_SIZE, ED25519_PUBLIC_KEY_SIZE,
    ED25519_SIGNATURE_SIZE,
};
pub use transcode::transcode;
#[cfg(feature = "web")]
pub use web::WebRng;
pub use xor::xor;
pub use zero::{is_zero, zeroize};
