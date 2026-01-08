use criterion::{criterion_group, criterion_main};

mod base;
mod blake2;
mod chacha20poly1305;
mod ed25519;
mod hkdf;
mod hmac;
mod pbkdf2;
mod rng;
mod sha2;
mod x25519;

criterion_group!(
    bench,
    base::bench,
    blake2::bench,
    chacha20poly1305::bench,
    ed25519::bench,
    hkdf::bench,
    hmac::bench,
    pbkdf2::bench,
    rng::bench,
    sha2::bench,
    x25519::bench,
);
criterion_main!(bench);
