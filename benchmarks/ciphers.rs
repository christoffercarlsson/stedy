use {
    criterion::Criterion,
    stedy::ciphers::{ChaCha20, Salsa20, XChaCha20, XSalsa20},
};

#[cfg(feature = "aes")]
use stedy::ciphers::{Aes128Ctr, Aes256Ctr};

pub fn bench(c: &mut Criterion) {
    let key = [
        128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145,
        146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
    ];
    let nonce = [7, 0, 0, 0, 64, 65, 66, 67, 68, 69, 70, 71];
    let message = [
        76, 97, 100, 105, 101, 115, 32, 97, 110, 100, 32, 71, 101, 110, 116, 108, 101, 109, 101,
        110, 32, 111, 102, 32, 116, 104, 101, 32, 99, 108, 97, 115, 115, 32, 111, 102, 32, 39, 57,
        57, 58, 32, 73, 102, 32, 73, 32, 99, 111, 117, 108, 100, 32, 111, 102, 102, 101, 114, 32,
        121, 111, 117, 32, 111, 110, 108, 121, 32, 111, 110, 101, 32, 116, 105, 112, 32, 102, 111,
        114, 32, 116, 104, 101, 32, 102, 117, 116, 117, 114, 101, 44, 32, 115, 117, 110, 115, 99,
        114, 101, 101, 110, 32, 119, 111, 117, 108, 100, 32, 98, 101, 32, 105, 116, 46,
    ];

    #[cfg(feature = "aes")]
    {
        let key = [
            254, 255, 233, 146, 134, 101, 115, 28, 109, 106, 143, 148, 103, 48, 131, 8,
        ];

        c.bench_function(&crate::aes_id("aes128ctr"), |b| {
            let mut message = message;
            b.iter(|| Aes128Ctr::new(&key, &nonce).apply_keystream(&mut message));
        });
    }

    #[cfg(feature = "aes")]
    c.bench_function(&crate::aes_id("aes256ctr"), |b| {
        let mut message = message;
        b.iter(|| Aes256Ctr::new(&key, &nonce).apply_keystream(&mut message));
    });

    c.bench_function("chacha20", |b| {
        let mut message = message;
        b.iter(|| ChaCha20::new(&key, &nonce).apply_keystream(&mut message));
    });

    c.bench_function("salsa20", |b| {
        let nonce = [7, 0, 0, 0, 64, 65, 66, 67];
        let mut message = message;
        b.iter(|| Salsa20::new(&key, &nonce).apply_keystream(&mut message));
    });

    let nonce = [
        7, 0, 0, 0, 64, 65, 66, 67, 68, 69, 70, 71, 7, 0, 0, 0, 64, 65, 66, 67, 68, 69, 70, 71,
    ];

    c.bench_function("xchacha20", |b| {
        let mut message = message;
        b.iter(|| XChaCha20::new(&key, &nonce).apply_keystream(&mut message));
    });

    c.bench_function("xsalsa20", |b| {
        let mut message = message;
        b.iter(|| XSalsa20::new(&key, &nonce).apply_keystream(&mut message));
    });
}
