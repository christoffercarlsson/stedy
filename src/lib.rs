mod chacha20;
mod hkdf_sha256;
mod hkdf_sha512;
mod hmac_sha256;
mod hmac_sha512;
mod poly1305;
mod sha256;
mod sha512;
mod verify;
mod xor;

#[derive(Debug)]
pub enum Error {
    InvalidInput,
    LimitExceeded,
    Verification,
}

pub use hkdf_sha256::hkdf_sha256;
pub use hkdf_sha512::hkdf_sha512;
pub use hmac_sha256::{hmac_sha256, hmac_sha256_verify, HmacSha256};
pub use hmac_sha512::{hmac_sha512, hmac_sha512_verify, HmacSha512};
pub use sha256::{sha256, Sha256};
pub use sha512::{sha512, Sha512};
pub use xor::xor;
