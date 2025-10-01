use criterion::{criterion_group, criterion_main};

mod chacha20poly1305;
mod ed25519;
mod hkdf_sha256;
mod hkdf_sha512;
mod hmac_sha256;
mod hmac_sha512;
mod sha256;
mod sha512;
mod sss;
mod x25519;
mod xor;

criterion_group!(
    benches,
    chacha20poly1305::bench,
    hkdf_sha256::bench,
    ed25519::bench,
    hkdf_sha512::bench,
    hmac_sha256::bench,
    hmac_sha512::bench,
    sha256::bench,
    sha512::bench,
    sss::bench,
    x25519::bench,
    xor::bench,
);
criterion_main!(benches);
