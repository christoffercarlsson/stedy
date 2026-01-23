mod shamir;

pub use shamir::{shamir_combine, shamir_split};

#[cfg(feature = "hazmat")]
pub use shamir::*;
