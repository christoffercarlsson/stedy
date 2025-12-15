use criterion::Criterion;
use stedy::{blake2b, blake2s};

pub fn bench(c: &mut Criterion) {
    let message = [72, 105, 32, 84, 104, 101, 114, 101];

    c.bench_function("blake2b", |b| b.iter(|| blake2b(&message)));

    c.bench_function("blake2s", |b| b.iter(|| blake2s(&message)));
}
