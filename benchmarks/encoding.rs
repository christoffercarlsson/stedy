use {
    criterion::Criterion,
    std::hint::black_box,
    stedy::encoding::{Encoding, decode, encode},
};

pub fn bench(c: &mut Criterion) {
    c.bench_function("base16_decode", |b| {
        let encoded = b"666F6F626172";
        b.iter(|| {
            let mut buffer = [0u8; 6];
            decode(Encoding::Base16, black_box(encoded), black_box(&mut buffer)).unwrap();
        });
    });

    c.bench_function("base32_decode", |b| {
        let encoded = b"MZXW6YTBOI======";
        b.iter(|| {
            let mut buffer = [0u8; 6];
            decode(Encoding::Base32, black_box(encoded), black_box(&mut buffer)).unwrap();
        });
    });

    c.bench_function("base64_decode", |b| {
        let encoded = b"Zm9vYmFy";
        b.iter(|| {
            let mut buffer = [0u8; 6];
            decode(Encoding::Base64, black_box(encoded), black_box(&mut buffer)).unwrap();
        });
    });

    c.bench_function("base16_encode", |b| {
        let decoded = b"foobar";
        b.iter(|| {
            let mut buffer = [0u8; 12];
            encode(Encoding::Base16, black_box(decoded), black_box(&mut buffer)).unwrap();
        });
    });

    c.bench_function("base32_encode", |b| {
        let decoded = b"foobar";
        b.iter(|| {
            let mut buffer = [0u8; 16];
            encode(Encoding::Base32, black_box(decoded), black_box(&mut buffer)).unwrap();
        });
    });

    c.bench_function("base64_encode", |b| {
        let decoded = b"foobar";
        b.iter(|| {
            let mut buffer = [0u8; 8];
            encode(Encoding::Base64, black_box(decoded), black_box(&mut buffer)).unwrap();
        });
    });
}
