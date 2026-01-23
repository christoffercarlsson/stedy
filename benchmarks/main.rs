use criterion::{criterion_group, criterion_main};

mod aeads;
mod csprngs;
mod encoding;
mod hashes;
mod kdfs;
mod key_exchange;
mod macs;
mod signatures;

criterion_group!(
    bench,
    aeads::bench,
    csprngs::bench,
    encoding::bench,
    hashes::bench,
    kdfs::bench,
    macs::bench,
    key_exchange::bench,
    signatures::bench,
);
criterion_main!(bench);
