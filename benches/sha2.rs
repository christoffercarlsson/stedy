use {
    criterion::Criterion,
    stedy::{sha256, sha512},
};

pub fn bench(c: &mut Criterion) {
    let message = [72, 105, 32, 84, 104, 101, 114, 101];

    c.bench_function("sha256", |b| b.iter(|| sha256(&message)));

    c.bench_function("sha512", |b| b.iter(|| sha512(&message)));
}
