use {
    criterion::Criterion,
    stedy::hashes::{
        Blake2b, Blake2b160, Blake2b256, Blake2b384, Blake2b512, Blake2s, Blake2s128, Blake2s160,
        Blake2s224, Blake2s256, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha256, Sha384, Sha512,
        Shake128, Shake256,
    },
};

#[cfg(feature = "hazmat")]
use stedy::hashes::Sha1;

pub fn bench(c: &mut Criterion) {
    let key = [
        11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    ];
    let message = [72, 105, 32, 84, 104, 101, 114, 101];

    c.bench_function("blake2b_keyed", |b| {
        b.iter(|| {
            let mut hasher = Blake2b::<64>::new(Some(&key)).unwrap();
            hasher.update(&message);
            hasher.finalize()
        });
    });

    c.bench_function("blake2s_keyed", |b| {
        b.iter(|| {
            let mut hasher = Blake2s::<32>::new(Some(&key)).unwrap();
            hasher.update(&message);
            hasher.finalize()
        });
    });

    #[cfg(feature = "hazmat")]
    c.bench_function("sha1", |b| b.iter(|| Sha1::digest(&message)));

    c.bench_function("sha3_224", |b| b.iter(|| Sha3_224::digest(&message)));

    c.bench_function("sha3_256", |b| b.iter(|| Sha3_256::digest(&message)));

    c.bench_function("sha3_384", |b| b.iter(|| Sha3_384::digest(&message)));

    c.bench_function("sha3_512", |b| b.iter(|| Sha3_512::digest(&message)));

    c.bench_function("sha256", |b| b.iter(|| Sha256::digest(&message)));

    c.bench_function("sha384", |b| b.iter(|| Sha384::digest(&message)));

    c.bench_function("sha512", |b| b.iter(|| Sha512::digest(&message)));

    c.bench_function("shake128", |b| {
        let mut output = [0u8; 32];
        b.iter(|| Shake128::digest(&message, &mut output));
    });

    c.bench_function("shake256", |b| {
        let mut output = [0u8; 64];
        b.iter(|| Shake256::digest(&message, &mut output));
    });

    c.bench_function("shake128_reader", |b| {
        let mut hasher = Shake128::new();
        hasher.update(&message);
        let mut reader = hasher.finalize_xof();
        let mut output = [0u8; 168];
        b.iter(|| reader.read(&mut output));
    });

    c.bench_function("shake256_reader", |b| {
        let mut hasher = Shake256::new();
        hasher.update(&message);
        let mut reader = hasher.finalize_xof();
        let mut output = [0u8; 136];
        b.iter(|| reader.read(&mut output));
    });

    c.bench_function("blake2b160", |b| b.iter(|| Blake2b160::digest(&message)));

    c.bench_function("blake2b256", |b| b.iter(|| Blake2b256::digest(&message)));

    c.bench_function("blake2b384", |b| b.iter(|| Blake2b384::digest(&message)));

    c.bench_function("blake2b512", |b| b.iter(|| Blake2b512::digest(&message)));

    c.bench_function("blake2s128", |b| b.iter(|| Blake2s128::digest(&message)));

    c.bench_function("blake2s160", |b| b.iter(|| Blake2s160::digest(&message)));

    c.bench_function("blake2s224", |b| b.iter(|| Blake2s224::digest(&message)));

    c.bench_function("blake2s256", |b| b.iter(|| Blake2s256::digest(&message)));
}
