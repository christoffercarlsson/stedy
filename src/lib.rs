#![no_std]

mod block;
mod sha256;
mod sha512;

pub use crate::{sha256::*, sha512::*};
