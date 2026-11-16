#![no_main]

use {
    libfuzzer_sys::fuzz_target,
    stedy::{
        aeads::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, XChaCha20Poly1305},
        traits::{Aead, ByteArray},
    },
};

fn mutate(bytes: &mut [u8], edits: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    for &[low, high, value] in edits.as_chunks::<3>().0 {
        bytes[usize::from(u16::from_le_bytes([low, high])) % bytes.len()] ^= value;
    }
}

fn raw<A: Aead>(data: &[u8]) {
    if data.len() < A::Nonce::SIZE + A::Tag::SIZE {
        return;
    }
    let (nonce, rest) = data.split_at(A::Nonce::SIZE);
    let (tag, ciphertext) = rest.split_at(A::Tag::SIZE);
    let mut buffer = ciphertext.to_vec();
    assert!(
        A::decrypt(
            &A::Key::new(),
            &A::Nonce::try_from_slice(nonce).unwrap(),
            None,
            &mut buffer,
            &A::Tag::try_from_slice(tag).unwrap(),
        )
        .is_err()
    );
    assert_eq!(buffer, ciphertext);
}

fn mutated<A: Aead>(data: &[u8]) {
    let Some((&seed, rest)) = data.split_first() else {
        return;
    };
    let (message, edits) = rest.split_at(rest.len() / 2);
    let mut key = A::Key::new();
    key.as_mut().fill(seed);
    let mut nonce = A::Nonce::new();
    nonce.as_mut().fill(seed);
    let aad = [seed; 16];
    let mut ciphertext = message.to_vec();
    let tag = A::encrypt(&key, &nonce, Some(&aad), &mut ciphertext).unwrap();
    let quarter = edits.len() / 4;
    let (ciphertext_edits, rest) = edits.split_at(quarter);
    let (tag_edits, rest) = rest.split_at(quarter);
    let (aad_edits, nonce_edits) = rest.split_at(quarter);
    let mut mutated_ciphertext = ciphertext.clone();
    let mut mutated_tag = tag.clone();
    let mut mutated_aad = aad;
    let mut mutated_nonce = nonce.clone();
    mutate(&mut mutated_ciphertext, ciphertext_edits);
    mutate(mutated_tag.as_mut(), tag_edits);
    mutate(&mut mutated_aad, aad_edits);
    mutate(mutated_nonce.as_mut(), nonce_edits);
    let mut buffer = mutated_ciphertext.clone();
    let decrypted = A::decrypt(
        &key,
        &mutated_nonce,
        Some(&mutated_aad),
        &mut buffer,
        &mutated_tag,
    );
    if mutated_ciphertext == ciphertext
        && mutated_tag.as_ref() == tag.as_ref()
        && mutated_aad == aad
        && mutated_nonce.as_ref() == nonce.as_ref()
    {
        decrypted.unwrap();
        assert_eq!(buffer, message);
    } else {
        assert!(decrypted.is_err());
        assert_eq!(buffer, mutated_ciphertext);
    }
}

fn aead<A: Aead>(mutated_input: bool, data: &[u8]) {
    if mutated_input {
        mutated::<A>(data);
    } else {
        raw::<A>(data);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, data)) = data.split_first() else {
        return;
    };
    let mutated_input = selector & 0x80 != 0;
    match selector % 4 {
        0 => aead::<ChaCha20Poly1305>(mutated_input, data),
        1 => aead::<XChaCha20Poly1305>(mutated_input, data),
        2 => aead::<Aes128Gcm>(mutated_input, data),
        _ => aead::<Aes256Gcm>(mutated_input, data),
    }
});
