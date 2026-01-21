use {
    criterion::Criterion,
    stedy::{Sha256, Sha512},
};

pub fn bench(c: &mut Criterion) {
    let message = [72, 105, 32, 84, 104, 101, 114, 101];

    c.bench_function("sha256", |b| b.iter(|| Sha256::digest(&message)));

    c.bench_function("sha512", |b| b.iter(|| Sha512::digest(&message)));
}
