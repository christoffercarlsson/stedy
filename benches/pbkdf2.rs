use {
    criterion::Criterion,
    stedy::{pbkdf2, Hmac, Sha256, Sha512},
};

pub fn bench(c: &mut Criterion) {
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
