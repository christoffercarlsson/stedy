use {
    criterion::Criterion,
    stedy::{
        csprngs::{ChaCha20Rng, HmacDrbg},
        hashes::{Sha256, Sha512},
    },
};

#[cfg(feature = "aes")]
use stedy::csprngs::{Aes128CtrRng, Aes256CtrRng};

pub fn bench(c: &mut Criterion) {
    let seed = [
        189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102, 238,
        246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 204, 202, 29, 227, 98, 39, 63,
        218, 245, 127, 170, 158, 94, 212, 115, 2, 22, 109, 212, 235, 42, 215, 1, 120, 200, 5, 161,
        173, 162, 48, 153, 5, 228, 51, 185, 144, 5, 108, 180, 103, 227, 33, 249, 180, 55, 133, 138,
        84, 78, 248, 192, 49, 168, 83, 96, 159, 150, 163, 210, 249, 205, 252, 103, 187, 90,
    ];

    #[cfg(feature = "aes")]
    c.bench_function(&crate::aes_id("aes128ctr_rng_fill"), |b| {
        let mut rng = Aes128CtrRng::from(&seed[..64].try_into().unwrap());
        let mut bytes = [0u8; 96];
        b.iter(|| rng.fill(&mut bytes));
    });

    #[cfg(feature = "aes")]
    c.bench_function(&crate::aes_id("aes256ctr_rng_fill"), |b| {
        let mut rng = Aes256CtrRng::from(&seed);
        let mut bytes = [0u8; 96];
        b.iter(|| rng.fill(&mut bytes));
    });

    c.bench_function("chacha20_rng_fill", |b| {
        let mut rng = ChaCha20Rng::from(&seed);
        let mut bytes = [0u8; 96];
        b.iter(|| rng.fill(&mut bytes));
    });

    c.bench_function("hmac_drbg_sha256_fill", |b| {
        let mut rng = HmacDrbg::<Sha256>::new(&seed[..32].try_into().unwrap());
        let mut bytes = [0u8; 96];
        b.iter(|| rng.fill(&mut bytes));
    });

    c.bench_function("hmac_drbg_sha512_fill", |b| {
        let mut rng = HmacDrbg::<Sha512>::new(&seed[..64].try_into().unwrap());
        let mut bytes = [0u8; 96];
        b.iter(|| rng.fill(&mut bytes));
    });
}
