use criterion::Criterion;
use stedy::{hmac_sha256, hmac_sha256_verify};

pub fn bench(c: &mut Criterion) {
    let key = [
        11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    ];
    let message = [72, 105, 32, 84, 104, 101, 114, 101];
    let code = [
        176, 52, 76, 97, 216, 219, 56, 83, 92, 168, 175, 206, 175, 11, 241, 43, 136, 29, 194, 0,
        201, 131, 61, 167, 38, 233, 55, 108, 46, 50, 207, 247,
    ];

    c.bench_function("hmac_sha256", |b| b.iter(|| hmac_sha256(&key, &message)));

    c.bench_function("hmac_sha256_verify", |b| {
        b.iter(|| hmac_sha256_verify(&key, &message, &code))
    });
}
