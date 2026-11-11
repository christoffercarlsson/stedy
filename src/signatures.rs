mod ecdsa;
mod ed25519;
mod eddsa;
mod ml_dsa;
mod p256;
mod p384;
mod p521;

pub(crate) use {
    ecdsa::Ecdsa,
    eddsa::{Eddsa, HashEddsa},
};
pub use {
    ed25519::*,
    ml_dsa::{MlDsa44, MlDsa65, MlDsa87},
    p256::*,
    p384::*,
    p521::*,
};

#[cfg(feature = "hazmat")]
pub use ml_dsa::{MlDsa44With, MlDsa65With, MlDsa87With, MlDsaNtt};

#[cfg(not(feature = "hazmat"))]
pub(crate) use ml_dsa::MlDsaNtt;
