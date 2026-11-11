mod blake2b;
mod blake2s;
mod keccak;
#[cfg(feature = "hazmat")]
mod sha1;
mod sha256;
mod sha3;
mod sha384;
mod sha512;
mod shake;

pub(crate) use {
    keccak::KeccakF1600,
    sha3::{Sha3_256With, Sha3_512With},
    shake::{Shake128With, Shake256With},
};

pub use {
    blake2b::*,
    blake2s::*,
    sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512},
    sha256::*,
    sha384::*,
    sha512::*,
    shake::{Shake128, Shake128Reader, Shake256, Shake256Reader},
};

#[cfg(feature = "hazmat")]
pub use sha1::*;
