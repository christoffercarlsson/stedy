mod hmac;
mod sha256;
mod sha512;
mod verify;
mod xor;

#[derive(Debug)]
pub enum Error {
    Verification,
}

pub use hmac::{HmacSha256, HmacSha512};
pub use sha256::{sha256, Sha256};
pub use sha512::{sha512, Sha512};
pub use xor::xor;
