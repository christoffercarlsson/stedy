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

#[cfg(feature = "argon2")]
pub(crate) use blake2b::Blake2bVar;

pub(crate) use {
    keccak::{KeccakF1600, Sponge},
    sha3::{Sha3_256With, Sha3_512With},
    shake::{Shake128With, Shake256With},
};

pub use {
    blake2b::{Blake2b, Blake2b160, Blake2b256, Blake2b384, Blake2b512},
    blake2s::*,
    sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512},
    sha256::*,
    sha384::*,
    sha512::*,
    shake::{Shake128, Shake128Reader, Shake256, Shake256Reader},
};

#[cfg(feature = "hazmat")]
pub use sha1::*;
