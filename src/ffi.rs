mod blake2b;
mod blake2s;
mod chacha20poly1305;
mod ed25519;
mod hkdf;
mod hmac_sha1;
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

#[panic_handler]
#[inline(never)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub use {
    blake2b::*, blake2s::*, chacha20poly1305::*, ed25519::*, hkdf::*, hmac_sha1::*, hmac_sha256::*,
    hmac_sha512::*, pad::*, pbkdf2::*, rng::*, sha256::*, sha512::*, verify::*, wipe::*, x25519::*,
};
