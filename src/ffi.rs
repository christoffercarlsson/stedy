mod blake2b;

#[panic_handler]
#[inline(never)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub use blake2b::*;
