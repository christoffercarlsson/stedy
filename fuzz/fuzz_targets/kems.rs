#![no_main]

use {
    libfuzzer_sys::fuzz_target,
    stedy::{
        csprngs::ChaCha20Rng,
        kems::{MlKem512, MlKem768, MlKem1024, XWing},
        traits::{ByteArray, Kem},
    },
};

fn mutate(bytes: &mut [u8], edits: &[u8]) -> bool {
    let mut changed = false;
    for &[low, high, value] in edits.as_chunks::<3>().0 {
        let index = usize::from(u16::from_le_bytes([low, high])) % bytes.len();
        bytes[index] ^= value;
        changed |= value != 0;
    }
    changed
}

fn raw<K: Kem>(data: &[u8]) {
    if data.len() >= K::PublicKey::SIZE {
        let public_key = K::PublicKey::try_from_slice(&data[..K::PublicKey::SIZE]).unwrap();
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let _ = K::encapsulate(&public_key, &mut rng);
    }
    if data.len() >= K::PrivateKey::SIZE + K::Ciphertext::SIZE {
        let (private_key, ciphertext) = data.split_at(K::PrivateKey::SIZE);
        let private_key = K::PrivateKey::try_from_slice(private_key).unwrap();
        let ciphertext = K::Ciphertext::try_from_slice(&ciphertext[..K::Ciphertext::SIZE]).unwrap();
        let _ = K::decapsulate(&private_key, &ciphertext);
    }
}

fn mutated<K: Kem>(data: &[u8]) {
    let Some((&seed, edits)) = data.split_first() else {
        return;
    };
    let mut rng = ChaCha20Rng::from(&[seed; 96]);
    let (mut private_key, mut public_key) = K::generate_key_pair(&mut rng).unwrap();
    let (shared_secret, ciphertext) = K::encapsulate(&public_key, &mut rng).unwrap();
    let third = edits.len() / 3;
    let (public_key_edits, rest) = edits.split_at(third);
    let (ciphertext_edits, private_key_edits) = rest.split_at(third);
    mutate(public_key.as_mut(), public_key_edits);
    let _ = K::encapsulate(&public_key, &mut rng);
    let mut mutated_ciphertext = ciphertext.clone();
    let changed = mutate(mutated_ciphertext.as_mut(), ciphertext_edits);
    let decapsulated = K::decapsulate(&private_key, &mutated_ciphertext).unwrap();
    if !changed {
        assert_eq!(decapsulated.as_ref(), shared_secret.as_ref());
    }
    mutate(private_key.as_mut(), private_key_edits);
    let _ = K::decapsulate(&private_key, &ciphertext);
}

fn kem<K: Kem>(mutated_input: bool, data: &[u8]) {
    if mutated_input {
        mutated::<K>(data);
    } else {
        raw::<K>(data);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, data)) = data.split_first() else {
        return;
    };
    let mutated_input = selector & 0x80 != 0;
    match selector % 4 {
        0 => kem::<MlKem512>(mutated_input, data),
        1 => kem::<MlKem768>(mutated_input, data),
        2 => kem::<MlKem1024>(mutated_input, data),
        _ => kem::<XWing>(mutated_input, data),
    }
});
