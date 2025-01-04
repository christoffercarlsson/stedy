use crate::{block::Block, chacha20::ChaCha20, poly1305::Poly1305, verify::verify, Error};

type ChaCha20Block = Block<64>;

pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> Result<[u8; 16], Error> {
    if plaintext.is_empty() || plaintext.len() != ciphertext.len() {
        return Err(Error::Encryption);
    }
    let mac = encrypt(key, nonce, plaintext, ciphertext);
    let tag = calculate_tag(mac, aad, ciphertext);
    Ok(tag)
}

pub fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
    ciphertext: &[u8],
    tag: &[u8; 16],
    plaintext: &mut [u8],
) -> Result<(), Error> {
    if ciphertext.is_empty() || ciphertext.len() != plaintext.len() {
        return Err(Error::Decryption);
    }
    let mac = encrypt(key, nonce, ciphertext, plaintext);
    verify_tag(mac, aad, ciphertext, tag).or(Err(Error::Decryption))
}

fn encrypt(key: &[u8; 32], nonce: &[u8; 12], input: &[u8], output: &mut [u8]) -> Poly1305 {
    let mut cipher = create_cipher(key, nonce);
    let mac = create_mac(&mut cipher);
    let mut block = ChaCha20Block::new();
    let (head, tail) = block.blocks(input);
    let offset = if let Some(head) = head {
        apply_keystream(&mut cipher, &head, &mut output[0..64]);
        64
    } else {
        0
    };
    for (begin, end) in tail {
        let begin = offset + begin;
        let end = offset + end;
        apply_keystream(&mut cipher, &input[begin..end], &mut output[begin..end]);
    }
    let remaining = block.remaining();
    if !remaining.is_empty() {
        let offset = output.len() - remaining.len();
        apply_keystream(&mut cipher, remaining, &mut output[offset..]);
    }
    mac
}

fn create_cipher(key: &[u8; 32], nonce: &[u8; 12]) -> ChaCha20 {
    let k = [
        u32::from_le_bytes(key[0..4].try_into().unwrap()),
        u32::from_le_bytes(key[4..8].try_into().unwrap()),
        u32::from_le_bytes(key[8..12].try_into().unwrap()),
        u32::from_le_bytes(key[12..16].try_into().unwrap()),
        u32::from_le_bytes(key[16..20].try_into().unwrap()),
        u32::from_le_bytes(key[20..24].try_into().unwrap()),
        u32::from_le_bytes(key[24..28].try_into().unwrap()),
        u32::from_le_bytes(key[28..32].try_into().unwrap()),
    ];
    let n = [
        u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
        u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
        u32::from_le_bytes(nonce[8..12].try_into().unwrap()),
    ];
    ChaCha20::new(&k, &n)
}

fn create_mac(cipher: &mut ChaCha20) -> Poly1305 {
    let mut key = [0u8; 32];
    let block = cipher.next();
    for (i, n) in block.iter().enumerate().take(8) {
        let begin = i * 4;
        let end = begin + 4;
        key[begin..end].copy_from_slice(&n.to_le_bytes());
    }
    Poly1305::new(&key)
}

fn apply_keystream(cipher: &mut ChaCha20, input: &[u8], output: &mut [u8]) {
    let mut keystream = [0u8; 64];
    let block = cipher.next();
    for (i, n) in block.iter().enumerate() {
        let begin = i * 4;
        let end = begin + 4;
        keystream[begin..end].copy_from_slice(&n.to_le_bytes());
    }
    output.copy_from_slice(input);
    for (i, byte) in output.iter_mut().enumerate() {
        *byte ^= keystream[i];
    }
}

fn calculate_tag(mut mac: Poly1305, aad: Option<&[u8]>, ciphertext: &[u8]) -> [u8; 16] {
    let aad = aad.unwrap_or(&[]);
    mac.update_padded(aad);
    mac.update_padded(ciphertext);
    mac.update(&(aad.len() as u64).to_le_bytes());
    mac.update(&(ciphertext.len() as u64).to_le_bytes());
    mac.finalize()
}

fn verify_tag(
    mac: Poly1305,
    aad: Option<&[u8]>,
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<(), Error> {
    verify(tag, &calculate_tag(mac, aad, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20poly1305() {
        let key = [
            173, 204, 82, 11, 56, 19, 130, 35, 125, 5, 166, 64, 10, 125, 251, 205, 7, 113, 182,
            170, 158, 219, 121, 102, 19, 29, 222, 246, 175, 33, 241, 190,
        ];
        let nonce = [145, 131, 205, 243, 168, 186, 115, 151, 182, 178, 213, 213];
        let aad = [179, 52, 55, 84, 21, 246, 33, 92, 11, 248, 154, 154];
        let message = [
            149, 130, 149, 97, 156, 241, 179, 111, 11, 71, 70, 99, 192, 188, 121, 235,
        ];
        let mut plaintext = [0u8; 16];
        let mut ciphertext = [0u8; 16];
        let tag =
            chacha20poly1305_encrypt(&key, &nonce, Some(&aad), &message, &mut ciphertext).unwrap();
        assert_eq!(
            ciphertext,
            [133, 44, 20, 27, 66, 57, 163, 31, 238, 218, 3, 85, 13, 112, 162, 190]
        );
        assert_eq!(
            tag,
            [95, 197, 146, 135, 185, 45, 63, 207, 125, 102, 241, 61, 239, 177, 27, 13]
        );
        chacha20poly1305_decrypt(&key, &nonce, Some(&aad), &ciphertext, &tag, &mut plaintext)
            .unwrap();
        assert_eq!(plaintext, message);
    }
}
