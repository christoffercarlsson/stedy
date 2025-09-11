use criterion::Criterion;
use stedy::{hmac_sha512, hmac_sha512_verify};

pub fn bench(c: &mut Criterion) {
    let key = [
        11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    ];
    let message = [72, 105, 32, 84, 104, 101, 114, 101];
    let code = [
        135, 170, 124, 222, 165, 239, 97, 157, 79, 240, 180, 36, 26, 29, 108, 176, 35, 121, 244,
        226, 206, 78, 194, 120, 122, 208, 179, 5, 69, 225, 124, 222, 218, 168, 51, 183, 214, 184,
        167, 2, 3, 139, 39, 78, 174, 163, 244, 228, 190, 157, 145, 78, 235, 97, 241, 112, 46, 105,
        108, 32, 58, 18, 104, 84,
    ];

    c.bench_function("hmac_sha512", |b| b.iter(|| hmac_sha512(&key, &message)));

    c.bench_function("hmac_sha512_verify", |b| {
        b.iter(|| hmac_sha512_verify(&key, &message, &code))
    });
}
