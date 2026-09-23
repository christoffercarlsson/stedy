use {
    criterion::Criterion,
    stedy::{
        hashes::{Sha256, Sha512},
        kdfs::{pbkdf2, Hkdf},
        macs::Hmac,
    },
};

#[cfg(feature = "argon2")]
use stedy::kdfs::{argon2, Argon2Params, Argon2Variant};

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

    #[cfg(feature = "argon2")]
    {
        let password = [1u8; 32];
        let salt = [2u8; 16];
        let secret = [3u8; 8];
        let associated_data = [4u8; 12];

        c.bench_function("argon2d", |b| {
            b.iter(|| {
                let mut output = [0u8; 32];
                argon2(
                    Argon2Params::new(Argon2Variant::Argon2d),
                    &password,
                    &salt,
                    Some(&secret),
                    Some(&associated_data),
                    &mut output,
                )
            })
        });

        c.bench_function("argon2i", |b| {
            b.iter(|| {
                let mut output = [0u8; 32];
                argon2(
                    Argon2Params::new(Argon2Variant::Argon2i),
                    &password,
                    &salt,
                    Some(&secret),
                    Some(&associated_data),
                    &mut output,
                )
            })
        });

        c.bench_function("argon2id", |b| {
            b.iter(|| {
                let mut output = [0u8; 32];
                argon2(
                    Argon2Params::new(Argon2Variant::Argon2id),
                    &password,
                    &salt,
                    Some(&secret),
                    Some(&associated_data),
                    &mut output,
                )
            })
        });
    }
}
