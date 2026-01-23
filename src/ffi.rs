#![allow(clippy::missing_safety_doc, clippy::unwrap_used)]
mod aeads;
mod csprngs;
mod encoding;
mod hashes;
mod kdfs;
mod key_exchange;
mod macs;
mod signatures;
mod utils;

#[cfg(not(test))]
#[panic_handler]
#[inline(never)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub use {
    aeads::*, csprngs::*, encoding::*, hashes::*, kdfs::*, key_exchange::*, macs::*, signatures::*,
    utils::*,
};
