use {
    criterion::Criterion,
    std::hint::black_box,
    stedy::{csprngs::ChaCha20Rng, secret_sharing::Shamir},
};

pub fn bench(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::from(&[0u8; 96]);
    let secret = [
        189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102, 238,
        246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 204,
    ];

    c.bench_function("shamir_split", |b| {
        let mut output = [0u8; 108];
        b.iter(|| {
            Shamir::split::<2, 3>(
                black_box(&mut rng),
                black_box(&secret),
                black_box(&mut output),
            )
            .map(|shares| shares.len())
        });
    });

    c.bench_function("shamir_combine", |b| {
        let mut output = [0u8; 108];
        let [first, second, _] = Shamir::split::<2, 3>(&mut rng, &secret, &mut output).unwrap();
        let mut combined = [0u8; 32];
        b.iter(|| Shamir::combine([first, second], black_box(&mut combined)).map(<[u8]>::len));
    });
}
