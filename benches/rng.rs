use {criterion::Criterion, stedy::Rng};

pub fn bench(c: &mut Criterion) {
    c.bench_function("rng_fill", |b| {
        let seed = [
            128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144,
            145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
        ];
        let mut rng = Rng::from(seed);
        let mut bytes = [0u8; 96];
        b.iter(|| rng.fill(&mut bytes))
    });
}
