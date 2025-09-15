use criterion::Criterion;
use stedy::{x25519_key_exchange, x25519_public_key};

pub fn bench(c: &mut Criterion) {
    let alice_private_key = [
        119, 7, 109, 10, 115, 24, 165, 125, 60, 22, 193, 114, 81, 178, 102, 69, 223, 76, 47, 135,
        235, 192, 153, 42, 177, 119, 251, 165, 29, 185, 44, 42,
    ];
    let bob_public_key = [
        222, 158, 219, 125, 123, 125, 193, 180, 211, 91, 97, 194, 236, 228, 53, 55, 63, 131, 67,
        200, 91, 120, 103, 77, 173, 252, 126, 20, 111, 136, 43, 79,
    ];

    c.bench_function("x25519_public_key", |b| {
        b.iter(|| x25519_public_key(&alice_private_key))
    });

    c.bench_function("x25519_key_exchange", |b| {
        b.iter(|| x25519_key_exchange(&alice_private_key, &bob_public_key))
    });
}
