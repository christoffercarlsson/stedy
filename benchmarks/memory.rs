use {
    criterion::Criterion,
    std::hint::black_box,
    stedy::memory::{constant_time_eq, wipe},
};

pub fn bench(c: &mut Criterion) {
    let a = [
        189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102, 238,
        246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 204,
    ];

    c.bench_function("constant_time_eq", |b| {
        let b_bytes = a;
        b.iter(|| constant_time_eq(black_box(&a), black_box(&b_bytes)));
    });

    c.bench_function("wipe", |b| {
        let mut bytes = a;
        b.iter(|| wipe(black_box(&mut bytes)));
    });
}
