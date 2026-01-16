#![allow(clippy::missing_safety_doc, clippy::unwrap_used)]
mod base;
mod blake2b160;
mod blake2b256;
mod blake2b384;
mod blake2b512;
mod blake2s128;
mod blake2s160;
mod blake2s224;
mod blake2s256;
mod chacha20poly1305;
mod ed25519;
mod hkdf;
mod hmac_sha256;
mod hmac_sha512;
mod pad;
mod pbkdf2;
mod rng;
mod sha256;
mod sha512;
mod verify;
mod wipe;
mod x25519;
mod xor;

#[cfg(not(test))]
#[panic_handler]
#[inline(never)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub use {
    base::*, blake2b160::*, blake2b256::*, blake2b384::*, blake2b512::*, blake2s128::*,
    blake2s160::*, blake2s224::*, blake2s256::*, chacha20poly1305::*, ed25519::*, hkdf::*,
    hmac_sha256::*, hmac_sha512::*, pad::*, pbkdf2::*, rng::*, sha256::*, sha512::*, verify::*,
    wipe::*, x25519::*, xor::*,
};
