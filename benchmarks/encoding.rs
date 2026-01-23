use {
    criterion::Criterion,
    stedy::encoding::{decode, encode, Encoding},
};

pub fn bench(c: &mut Criterion) {
    c.bench_function("base64_encode", |b| {
        let decoded = b"foobar";
        b.iter(|| {
            let mut buffer = [0u8; 8];
            encode(Encoding::Base64, decoded, &mut buffer).unwrap();
        })
    });

    c.bench_function("base64_decode", |b| {
        let encoded = b"Zm9vYmFy";
        b.iter(|| {
            let mut buffer = [0u8; 6];
            decode(Encoding::Base64, encoded, &mut buffer).unwrap();
        })
    });

    c.bench_function("base32_encode", |b| {
        let decoded = b"foobar";
        b.iter(|| {
            let mut buffer = [0u8; 16];
            encode(Encoding::Base32, decoded, &mut buffer).unwrap();
        })
    });

    c.bench_function("base32_decode", |b| {
        let encoded = b"MZXW6YTBOI======";
        b.iter(|| {
            let mut buffer = [0u8; 6];
            decode(Encoding::Base32, encoded, &mut buffer).unwrap();
        })
    });

    c.bench_function("base16_encode", |b| {
        let decoded = b"foobar";
        b.iter(|| {
            let mut buffer = [0u8; 12];
            encode(Encoding::Base16, decoded, &mut buffer).unwrap();
        })
    });

    c.bench_function("base16_decode", |b| {
        let encoded = b"666F6F626172";
        b.iter(|| {
            let mut buffer = [0u8; 6];
            decode(Encoding::Base16, encoded, &mut buffer).unwrap();
        })
    });
}
