use {
    criterion::Criterion,
    stedy::{
        hashes::{Sha256, Sha512},
        kdfs::{pbkdf2, Hkdf},
        macs::Hmac,
    },
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

    let password = b"password";
    let salt = b"salt";
    let iterations = 4096;

    c.bench_function("pbkdf2_hmac_sha256", |b| {
        b.iter(|| {
            let mut output = [0u8; 32];
            pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut output);
        })
    });

    c.bench_function("pbkdf2_hmac_sha512", |b| {
        b.iter(|| {
            let mut output = [0u8; 64];
            pbkdf2::<Hmac<Sha512>>(password, salt, iterations, &mut output);
        })
    });
}
