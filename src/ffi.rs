mod blake2b;
mod blake2s;
mod chacha20poly1305;

#[panic_handler]
#[inline(never)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub use {blake2b::*, blake2s::*, chacha20poly1305::*};
