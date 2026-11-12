use criterion::{Criterion, criterion_group, criterion_main};

mod aeads;
#[cfg(feature = "hazmat")]
mod ciphers;
mod csprngs;
mod encoding;
mod hashes;
mod kdfs;
mod kems;
mod key_exchange;
mod macs;
mod padding;
#[cfg(feature = "secret_sharing")]
mod secret_sharing;
mod signatures;
mod utils;

#[cfg(feature = "aes")]
fn aes_id(name: &str) -> String {
    let backend = if stedy::aeads::Aes128Gcm::is_accelerated() {
        "hardware"
    } else {
        "software"
    };
    format!("{name}/{backend}")
}

fn bench(c: &mut Criterion) {
    aeads::bench(c);
    #[cfg(feature = "hazmat")]
    ciphers::bench(c);
    csprngs::bench(c);
    encoding::bench(c);
    hashes::bench(c);
    kdfs::bench(c);
    kems::bench(c);
    key_exchange::bench(c);
    macs::bench(c);
    padding::bench(c);
    #[cfg(feature = "secret_sharing")]
    secret_sharing::bench(c);
    signatures::bench(c);
    utils::bench(c);
}

criterion_group!(benches, bench);
criterion_main!(benches);
