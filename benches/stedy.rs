use criterion::{criterion_group, criterion_main};

mod chacha20poly1305;
mod ed25519;
mod hkdf;
mod hmac;
mod pbkdf2;
mod sha256;
mod sha512;
mod sss;
mod x25519;

criterion_group!(
    benches,
    chacha20poly1305::bench,
    ed25519::bench,
    hkdf::bench,
    hmac::bench,
    pbkdf2::bench,
    sha256::bench,
    sha512::bench,
    sss::bench,
    x25519::bench,
);
criterion_main!(benches);
