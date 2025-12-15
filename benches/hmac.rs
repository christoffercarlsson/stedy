use criterion::Criterion;
use stedy::{
    hmac_sha1, hmac_sha1_verify, hmac_sha256, hmac_sha256_verify, hmac_sha512, hmac_sha512_verify,
};

pub fn bench(c: &mut Criterion) {
    let key = [
        11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    ];
    let message = [72, 105, 32, 84, 104, 101, 114, 101];

    c.bench_function("hmac_sha1", |b| b.iter(|| hmac_sha1(&key, &message)));

    c.bench_function("hmac_sha1_verify", |b| {
        let code = [
            182, 23, 49, 134, 85, 5, 114, 100, 226, 139, 192, 182, 251, 55, 140, 142, 241, 70, 190,
            0,
        ];
        b.iter(|| hmac_sha1_verify(&key, &message, &code))
    });

    c.bench_function("hmac_sha256", |b| b.iter(|| hmac_sha256(&key, &message)));

    c.bench_function("hmac_sha256_verify", |b| {
        let code = [
            176, 52, 76, 97, 216, 219, 56, 83, 92, 168, 175, 206, 175, 11, 241, 43, 136, 29, 194,
            0, 201, 131, 61, 167, 38, 233, 55, 108, 46, 50, 207, 247,
        ];
        b.iter(|| hmac_sha256_verify(&key, &message, &code))
    });

    c.bench_function("hmac_sha512", |b| b.iter(|| hmac_sha512(&key, &message)));

    c.bench_function("hmac_sha512_verify", |b| {
        let code = [
            135, 170, 124, 222, 165, 239, 97, 157, 79, 240, 180, 36, 26, 29, 108, 176, 35, 121,
            244, 226, 206, 78, 194, 120, 122, 208, 179, 5, 69, 225, 124, 222, 218, 168, 51, 183,
            214, 184, 167, 2, 3, 139, 39, 78, 174, 163, 244, 228, 190, 157, 145, 78, 235, 97, 241,
            112, 46, 105, 108, 32, 58, 18, 104, 84,
        ];
        b.iter(|| hmac_sha512_verify(&key, &message, &code))
    });
}
