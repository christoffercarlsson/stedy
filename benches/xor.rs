use criterion::Criterion;
use stedy::xor;

pub fn bench(c: &mut Criterion) {
    let x = [0, 186, 88, 78, 141, 119, 241, 56, 159, 38, 140, 216];
    let y = [0, 129, 129, 138, 254, 243, 236, 227, 82, 207, 10, 195];

    c.bench_function("xor", |b| {
        b.iter(|| {
            let mut z = [0u8; 12];
            xor(&x, &y, &mut z)
        })
    });
}
