use {
    criterion::Criterion,
    stedy::hashes::{Blake2b512, Blake2s256, Sha256, Sha512},
};

pub fn bench(c: &mut Criterion) {
    let message = [72, 105, 32, 84, 104, 101, 114, 101];

    c.bench_function("blake2b512", |b| b.iter(|| Blake2b512::digest(&message)));

    c.bench_function("blake2s256", |b| b.iter(|| Blake2s256::digest(&message)));

    c.bench_function("sha256", |b| b.iter(|| Sha256::digest(&message)));

    c.bench_function("sha512", |b| b.iter(|| Sha512::digest(&message)));
}
