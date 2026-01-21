use {
    criterion::Criterion,
    stedy::{Hkdf, Sha256, Sha512},
};

pub fn bench(c: &mut Criterion) {
    let ikm = [
        11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    ];
    let salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let info = [240, 241, 242, 243, 244, 245, 246, 247, 248, 249];

    c.bench_function("hkdf_sha256", |b| {
        b.iter(|| {
            let mut okm = [0; 42];
            Hkdf::<Sha256>::hkdf(&ikm, Some(&salt), Some(&info), &mut okm)
        })
    });

    c.bench_function("hkdf_sha512", |b| {
        b.iter(|| {
            let mut okm = [0; 42];
            Hkdf::<Sha512>::hkdf(&ikm, Some(&salt), Some(&info), &mut okm)
        })
    });
}
