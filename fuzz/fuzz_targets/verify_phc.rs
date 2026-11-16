#![no_main]

use {
    libfuzzer_sys::fuzz_target,
    stedy::kdfs::{Argon2, Argon2Params, Argon2Variant},
};

fn affordable(phc: &[u8]) -> bool {
    phc.split(|&byte| byte == b'$' || byte == b',')
        .all(|field| {
            let limit = match field.get(..2) {
                Some(b"m=") => 64,
                Some(b"t=") => 2,
                Some(b"p=") => 4,
                _ => return true,
            };
            field[2..]
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .try_fold(0u64, |value, &digit| {
                    let value = value * 10 + u64::from(digit - b'0');
                    (value <= limit).then_some(value)
                })
                .is_some()
        })
}

fn mutated(data: &[u8]) {
    let Some((&seed, edits)) = data.split_first() else {
        return;
    };
    let variant = [
        Argon2Variant::Argon2d,
        Argon2Variant::Argon2i,
        Argon2Variant::Argon2id,
    ][usize::from(seed % 3)];
    let params = Argon2Params::new(variant)
        .memory(8)
        .passes(1)
        .lanes(1)
        .threads(1);
    let mut buffer = [0u8; 256];
    let mut phc = Argon2::phc(params, &[seed], &[seed; 16], 32, &mut buffer)
        .unwrap()
        .to_vec();
    let mut changed = false;
    for &[position, value] in edits.as_chunks::<2>().0 {
        let index = usize::from(position) % phc.len();
        phc[index] ^= value;
        changed |= value != 0;
    }
    if !affordable(&phc) {
        return;
    }
    let verified = Argon2::verify_phc(&[seed], &phc);
    if !changed {
        assert!(verified.is_ok());
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, data)) = data.split_first() else {
        return;
    };
    if selector & 1 == 1 {
        mutated(data);
        return;
    }
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let (password, phc) = rest.split_at(usize::from(split).min(rest.len()));
    if affordable(phc) {
        let _ = Argon2::verify_phc(password, phc);
    }
});
