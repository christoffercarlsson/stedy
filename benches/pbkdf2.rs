use criterion::Criterion;
use stedy::{pbkdf2_hmac_sha256, pbkdf2_hmac_sha512};

pub fn bench(c: &mut Criterion) {
    let password = b"password";
    let salt = b"salt";
    let iterations = 4096;

    c.bench_function("pbkdf2_hmac_sha256_4096", |b| {
        b.iter(|| {
            let mut output = [0u8; 32];
            pbkdf2_hmac_sha256(password, salt, iterations, &mut output);
        })
    });

    c.bench_function("pbkdf2_hmac_sha512_4096", |b| {
        b.iter(|| {
            let mut output = [0u8; 64];
            pbkdf2_hmac_sha512(password, salt, iterations, &mut output);
        })
    });
}
