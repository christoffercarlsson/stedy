use {
    criterion::Criterion,
    std::hint::black_box,
    stedy::{elliptic_curves::Ristretto255, hashes::Sha512},
};

pub fn bench(c: &mut Criterion) {
    let element = [
        226, 242, 174, 10, 106, 188, 78, 113, 168, 132, 169, 97, 197, 0, 81, 95, 88, 227, 11, 106,
        165, 130, 221, 141, 182, 166, 89, 69, 224, 141, 45, 118,
    ];
    let other = [
        106, 73, 50, 16, 247, 73, 156, 209, 127, 236, 181, 16, 174, 12, 234, 35, 161, 16, 232, 213,
        185, 1, 248, 172, 173, 211, 9, 92, 115, 163, 185, 25,
    ];
    let scalar = [
        189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102, 238,
        246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 12,
    ];
    let uniform_bytes = [7u8; 64];

    c.bench_function("ristretto255_is_valid", |b| {
        b.iter(|| Ristretto255::is_valid(black_box(&element)));
    });

    c.bench_function("ristretto255_from_uniform_bytes", |b| {
        b.iter(|| Ristretto255::from_uniform_bytes(black_box(&uniform_bytes)));
    });

    c.bench_function("ristretto255_from_string", |b| {
        b.iter(|| Ristretto255::from_string::<Sha512>(b"context", b"message"));
    });

    c.bench_function("ristretto255_add", |b| {
        b.iter(|| Ristretto255::add(black_box(&element), black_box(&other)));
    });

    c.bench_function("ristretto255_sub", |b| {
        b.iter(|| Ristretto255::sub(black_box(&element), black_box(&other)));
    });

    c.bench_function("ristretto255_scalar_mult", |b| {
        b.iter(|| Ristretto255::scalar_mult(black_box(&scalar), black_box(&element)));
    });

    c.bench_function("ristretto255_scalar_mult_base", |b| {
        b.iter(|| Ristretto255::scalar_mult_base(black_box(&scalar)));
    });

    c.bench_function("ristretto255_scalar_mul", |b| {
        b.iter(|| Ristretto255::scalar_mul(black_box(&scalar), black_box(&scalar)));
    });

    c.bench_function("ristretto255_scalar_invert", |b| {
        b.iter(|| Ristretto255::scalar_invert(black_box(&scalar)));
    });
}
