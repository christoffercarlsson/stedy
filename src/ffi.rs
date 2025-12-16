mod blake2b;
mod blake2s;
mod chacha20poly1305;
mod ed25519;
mod hkdf;
mod hmac;
mod pad;

#[panic_handler]
#[inline(never)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub use {blake2b::*, blake2s::*, chacha20poly1305::*, ed25519::*, hkdf::*, hmac::*, pad::*};
