use crate::{block::Block, chacha::ChaCha20, poly1305::Poly1305, verify::verify, Error};

type ChaCha20Block = Block<64>;

pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
    message: &mut [u8],
) -> [u8; 16] {
    let mut cipher = ChaCha20::from(key, nonce);
    let mac = create_mac(&mut cipher);
    encrypt(&mut cipher, message);
    calculate_tag(mac, aad, message)
}

pub fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
    message: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), Error> {
    let mut cipher = ChaCha20::from(key, nonce);
    let mac = create_mac(&mut cipher);
    let t = calculate_tag(mac, aad, message);
    encrypt(&mut cipher, message);
    verify(tag, &t).or(Err(Error::Decryption))
}

fn encrypt(cipher: &mut ChaCha20, message: &mut [u8]) {
    let mut block = ChaCha20Block::new();
    let (head, tail) = block.blocks(message);
    let offset = if head.is_some() {
        cipher.apply_keystream(&mut message[..64]);
        64
    } else {
        0
    };
    for (begin, end) in tail {
        let begin = offset + begin;
        let end = offset + end;
        cipher.apply_keystream(&mut message[begin..end]);
    }
    let remaining = block.remaining();
    if !remaining.is_empty() {
        let offset = message.len() - remaining.len();
        cipher.apply_keystream(&mut message[offset..]);
    }
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

fn calculate_tag(mut mac: Poly1305, aad: Option<&[u8]>, ciphertext: &[u8]) -> [u8; 16] {
    let aad = aad.unwrap_or(&[]);
    mac.update_padded(aad);
    mac.update_padded(ciphertext);
    mac.update(&(aad.len() as u64).to_le_bytes());
    mac.update(&(ciphertext.len() as u64).to_le_bytes());
    mac.finalize()
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
        let mut message = [
            149, 130, 149, 97, 156, 241, 179, 111, 11, 71, 70, 99, 192, 188, 121, 235,
        ];
        let tag = chacha20poly1305_encrypt(&key, &nonce, Some(&aad), &mut message);
        assert_eq!(
            message,
            [133, 44, 20, 27, 66, 57, 163, 31, 238, 218, 3, 85, 13, 112, 162, 190]
        );
        assert_eq!(
            tag,
            [95, 197, 146, 135, 185, 45, 63, 207, 125, 102, 241, 61, 239, 177, 27, 13]
        );
        chacha20poly1305_decrypt(&key, &nonce, Some(&aad), &mut message, &tag).unwrap();
        assert_eq!(
            message,
            [149, 130, 149, 97, 156, 241, 179, 111, 11, 71, 70, 99, 192, 188, 121, 235]
        );
    }
}
