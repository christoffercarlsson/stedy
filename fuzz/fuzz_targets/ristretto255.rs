#![no_main]

use {libfuzzer_sys::fuzz_target, stedy::elliptic_curves::Ristretto255};

fuzz_target!(|data: &[u8]| {
    let Some((wide, _)) = data.split_first_chunk::<64>() else {
        return;
    };
    let (a, b) = wide.split_at(32);
    let (a, b) = (a.try_into().unwrap(), b.try_into().unwrap());
    if Ristretto255::is_valid(a) {
        assert_eq!(Ristretto255::add(a, b).is_ok(), Ristretto255::is_valid(b));
    } else {
        assert!(Ristretto255::add(a, b).is_err());
    }
    let _ = Ristretto255::sub(a, b);
    let _ = Ristretto255::scalar_mult(a, b);
    let _ = Ristretto255::scalar_mult_base(a);
    let _ = Ristretto255::scalar_add(a, b);
    let _ = Ristretto255::scalar_mul(a, b);
    let _ = Ristretto255::scalar_invert(a);
    assert!(Ristretto255::is_valid(&Ristretto255::from_uniform_bytes(
        wide
    )));
    let _ = Ristretto255::scalar_reduce(wide);
});
