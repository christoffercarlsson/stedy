mod blake2b;
mod blake2s;

#[panic_handler]
#[inline(never)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub use {blake2b::*, blake2s::*};
