use criterion::{criterion_group, criterion_main};

mod aeads;
mod csprngs;
mod encoding;
mod hashes;
mod kdfs;
mod kems;
mod key_exchange;
mod macs;
mod signatures;

#[cfg(feature = "aes")]
fn aes_id(name: &str) -> String {
    let backend = if stedy::aeads::Aes128Gcm::is_accelerated() {
        "hardware"
    } else {
        "software"
    };
    format!("{name}/{backend}")
}

criterion_group!(
    bench,
    aeads::bench,
    csprngs::bench,
    encoding::bench,
    hashes::bench,
    kdfs::bench,
    kems::bench,
    macs::bench,
    key_exchange::bench,
    signatures::bench,
);
criterion_main!(bench);
