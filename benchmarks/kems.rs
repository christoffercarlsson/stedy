use {
    criterion::Criterion,
    stedy::{
        csprngs::ChaCha20Rng,
        kems::{MlKem1024, MlKem512, MlKem768, XWing},
    },
};

pub fn bench(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::from(&[0u8; 96]);
    let seed = [90u8; 64];

    let (private_key, public_key) = MlKem512::key_pair(&seed);
    let (_, ciphertext) = MlKem512::encapsulate(&public_key, &mut rng).expect("valid public key");

    c.bench_function("ml_kem_512_key_pair", |b| {
        b.iter(|| MlKem512::key_pair(&seed))
    });

    c.bench_function("ml_kem_512_encapsulate", |b| {
        b.iter(|| MlKem512::encapsulate(&public_key, &mut rng))
    });

    c.bench_function("ml_kem_512_decapsulate", |b| {
        b.iter(|| MlKem512::decapsulate(&private_key, &ciphertext))
    });

    let (private_key, public_key) = MlKem768::key_pair(&seed);
    let (_, ciphertext) = MlKem768::encapsulate(&public_key, &mut rng).expect("valid public key");

    c.bench_function("ml_kem_768_key_pair", |b| {
        b.iter(|| MlKem768::key_pair(&seed))
    });

    c.bench_function("ml_kem_768_encapsulate", |b| {
        b.iter(|| MlKem768::encapsulate(&public_key, &mut rng))
    });

    c.bench_function("ml_kem_768_decapsulate", |b| {
        b.iter(|| MlKem768::decapsulate(&private_key, &ciphertext))
    });

    let (private_key, public_key) = MlKem1024::key_pair(&seed);
    let (_, ciphertext) = MlKem1024::encapsulate(&public_key, &mut rng).expect("valid public key");

    c.bench_function("ml_kem_1024_key_pair", |b| {
        b.iter(|| MlKem1024::key_pair(&seed))
    });

    c.bench_function("ml_kem_1024_encapsulate", |b| {
        b.iter(|| MlKem1024::encapsulate(&public_key, &mut rng))
    });

    c.bench_function("ml_kem_1024_decapsulate", |b| {
        b.iter(|| MlKem1024::decapsulate(&private_key, &ciphertext))
    });

    let seed = [90u8; 32];
    let (private_key, public_key) = XWing::key_pair(&seed);
    let (_, ciphertext) = XWing::encapsulate(&public_key, &mut rng).expect("valid public key");

    c.bench_function("x_wing_key_pair", |b| b.iter(|| XWing::key_pair(&seed)));

    c.bench_function("x_wing_encapsulate", |b| {
        b.iter(|| XWing::encapsulate(&public_key, &mut rng))
    });

    c.bench_function("x_wing_decapsulate", |b| {
        b.iter(|| XWing::decapsulate(&private_key, &ciphertext))
    });
}
