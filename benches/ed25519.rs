use criterion::Criterion;
use stedy::{ed25519_public_key, ed25519_sign, ed25519_verify};

pub fn bench(c: &mut Criterion) {
    let private_key = [
        157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73, 197,
        105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
    ];
    let public_key = [
        215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
    ];
    let message = [];
    let signature = [
        229, 86, 67, 0, 195, 96, 172, 114, 144, 134, 226, 204, 128, 110, 130, 138, 132, 135, 127,
        30, 184, 229, 217, 116, 216, 115, 224, 101, 34, 73, 1, 85, 95, 184, 130, 21, 144, 163, 59,
        172, 198, 30, 57, 112, 28, 249, 180, 107, 210, 91, 245, 240, 89, 91, 190, 36, 101, 81, 65,
        67, 142, 122, 16, 11,
    ];

    c.bench_function("ed25519_public_key", |b| {
        b.iter(|| ed25519_public_key(&private_key))
    });

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| ed25519_sign(&private_key, &message))
    });

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| ed25519_verify(&message, &public_key, &signature))
    });
}
