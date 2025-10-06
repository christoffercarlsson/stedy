use criterion::Criterion;
use stedy::{blake2b, blake2s};

pub fn bench(c: &mut Criterion) {
    let message = b"abc";

    c.bench_function("blake2b", |b| b.iter(|| blake2b(message)));

    c.bench_function("blake2s", |b| b.iter(|| blake2s(message)));
}
