use {
    criterion::Criterion,
    std::hint::black_box,
    stedy::padding::{pad_to_block, pad_to_capacity, unpad},
};

pub fn bench(c: &mut Criterion) {
    let unpadded = [72, 105, 32, 84, 104, 101, 114, 101];

    c.bench_function("pad_to_block", |b| {
        let mut buffer = [0u8; 16];
        b.iter(|| pad_to_block(black_box(&unpadded), black_box(&mut buffer), 16).map(<[u8]>::len));
    });

    c.bench_function("pad_to_capacity", |b| {
        let mut buffer = [0u8; 16];
        b.iter(|| pad_to_capacity(black_box(&unpadded), black_box(&mut buffer)).map(<[u8]>::len));
    });

    c.bench_function("unpad", |b| {
        let padded = [
            72, 105, 32, 84, 104, 101, 114, 101, 128, 0, 0, 0, 0, 0, 0, 0,
        ];
        b.iter(|| unpad(black_box(&padded)).map(<[u8]>::len));
    });
}
