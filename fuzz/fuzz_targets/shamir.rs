#![no_main]

use {libfuzzer_sys::fuzz_target, stedy::secret_sharing::Shamir};

fuzz_target!(|data: &[u8]| {
    let Some((&size, data)) = data.split_first() else {
        return;
    };
    let size = usize::from(size);
    if size == 0 || data.len() < 3 * size {
        return;
    }
    let shares = [
        &data[..size],
        &data[size..2 * size],
        &data[2 * size..3 * size],
    ];
    let mut secret = vec![0u8; size];
    let _ = Shamir::combine(shares, &mut secret);
});
