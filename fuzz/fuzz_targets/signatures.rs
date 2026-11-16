#![no_main]

use {
    libfuzzer_sys::fuzz_target,
    stedy::{
        csprngs::ChaCha20Rng,
        signatures::{Ed25519, MlDsa44, MlDsa65, MlDsa87, P256, P384, P521},
        traits::{ByteArray, SignatureScheme},
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

fn verify<S: SignatureScheme>(data: &[u8]) {
    if data.len() < S::PublicKey::SIZE + S::Signature::SIZE {
        return;
    }
    let (public_key, rest) = data.split_at(S::PublicKey::SIZE);
    let (signature, message) = rest.split_at(S::Signature::SIZE);
    let public_key = S::PublicKey::try_from_slice(public_key).unwrap();
    let signature = S::Signature::try_from_slice(signature).unwrap();
    let _ = S::verify(message, &public_key, &signature);
}

fn verify_mutated<S: SignatureScheme>(data: &[u8]) {
    let Some((&seed, edits)) = data.split_first() else {
        return;
    };
    let mut rng = ChaCha20Rng::from(&[seed; 96]);
    let (private_key, mut public_key) = S::generate_key_pair(&mut rng).unwrap();
    let mut signature = S::sign(&private_key, b"message").unwrap();
    let (public_key_edits, signature_edits) = edits.split_at(edits.len() / 2);
    let changed =
        mutate(public_key.as_mut(), public_key_edits) | mutate(signature.as_mut(), signature_edits);
    let verified = S::verify(b"message", &public_key, &signature);
    if !changed {
        assert!(verified.is_ok());
    }
}

fn scheme<S: SignatureScheme>(mutated: bool, data: &[u8]) {
    if mutated {
        verify_mutated::<S>(data);
    } else {
        verify::<S>(data);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, data)) = data.split_first() else {
        return;
    };
    let mutated = selector & 0x80 != 0;
    match selector % 7 {
        0 => scheme::<Ed25519>(mutated, data),
        1 => scheme::<P256>(mutated, data),
        2 => scheme::<P384>(mutated, data),
        3 => scheme::<P521>(mutated, data),
        4 => scheme::<MlDsa44>(mutated, data),
        5 => scheme::<MlDsa65>(mutated, data),
        _ => scheme::<MlDsa87>(mutated, data),
    }
});
