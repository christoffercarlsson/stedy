#![cfg_attr(not(feature = "std"), no_std)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod aeads;
#[cfg(not(feature = "hazmat"))]
mod ciphers;
#[cfg(feature = "hazmat")]
pub mod ciphers;
pub mod csprngs;
#[cfg(not(feature = "hazmat"))]
mod elliptic_curves;
#[cfg(feature = "hazmat")]
pub mod elliptic_curves;
pub mod encoding;
pub mod hashes;
pub mod kdfs;
pub mod kems;
pub mod key_exchange;
pub mod macs;
mod secret;
#[cfg(feature = "secret_sharing")]
pub mod secret_sharing;
pub mod signatures;
pub mod traits;
pub mod utils;

pub(crate) use secret::Secret;
