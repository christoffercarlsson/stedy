use {
    crate::{
        Error,
        ciphers::{ChaCha20, XChaCha20, XSalsa20},
        traits::{Authenticator, SeekableStreamCipher, Wipe},
        utils::{Block, Secret, constant_time_eq},
    },
    field::Poly1305FieldElement,
};

pub struct Poly1305 {
    a: Poly1305FieldElement,
    r: Poly1305FieldElement,
    s: Poly1305FieldElement,
    block: Block<{ Self::BLOCK_SIZE }>,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let (halves, _) = key.as_chunks::<16>();
        let mut r = Poly1305FieldElement::from(&halves[0]);
        r &= Poly1305FieldElement::R;
        Self {
            a: Poly1305FieldElement::ZERO,
            r,
            s: Poly1305FieldElement::from(&halves[1]),
            block: Block::<{ Self::BLOCK_SIZE }>::new(),
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        if let Some((head, tail)) = self.block.blocks(message) {
            self.process_block(head.get());
            for block in tail {
                self.process_block(block);
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let remaining = self.block.remaining();
        if !remaining.is_empty() {
            let n = Self::read_block(remaining);
            self.process_element(n);
        }
        self.a.canonical();
        self.a.add_truncating(self.s);
        self.a.into()
    }

    pub fn verify(self, code: &[u8; 16]) -> Result<(), Error> {
        let computed = Secret::from(self.finalize());
        if constant_time_eq(computed.get(), code) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

impl Authenticator<ChaCha20> for Poly1305 {
    type Output = [u8; 16];

    fn new(cipher: &mut ChaCha20) -> Self {
        Self::create_mac(cipher)
    }

    fn tag(mut self, ciphertext: &[u8], aad: Option<&[u8]>) -> Self::Output {
        self.calculate_tag(ciphertext, aad);
        self.finalize()
    }

    fn verify(mut self, ciphertext: &[u8], aad: Option<&[u8]>, tag: &Self::Output) -> bool {
        self.calculate_tag(ciphertext, aad);
        Poly1305::verify(self, tag).is_ok()
    }
}

impl Authenticator<XChaCha20> for Poly1305 {
    type Output = [u8; 16];

    fn new(cipher: &mut XChaCha20) -> Self {
        Self::create_mac(cipher)
    }

    fn tag(mut self, ciphertext: &[u8], aad: Option<&[u8]>) -> Self::Output {
        self.calculate_tag(ciphertext, aad);
        self.finalize()
    }

    fn verify(mut self, ciphertext: &[u8], aad: Option<&[u8]>, tag: &Self::Output) -> bool {
        self.calculate_tag(ciphertext, aad);
        Poly1305::verify(self, tag).is_ok()
    }
}

impl Authenticator<XSalsa20> for Poly1305 {
    type Output = [u8; 16];

    fn new(cipher: &mut XSalsa20) -> Self {
        let mut key = Secret::from([0u8; 32]);
        cipher
            .apply_keystream(key.get_mut())
            .expect("the first keystream block is always available");
        Self::new(key.get())
    }

    fn tag(mut self, ciphertext: &[u8], _aad: Option<&[u8]>) -> Self::Output {
        self.update(ciphertext);
        self.finalize()
    }

    fn verify(mut self, ciphertext: &[u8], _aad: Option<&[u8]>, tag: &Self::Output) -> bool {
        self.update(ciphertext);
        Poly1305::verify(self, tag).is_ok()
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.a.wipe();
        self.r.wipe();
        self.s.wipe();
    }
}

impl Poly1305 {
    const BLOCK_SIZE: usize = 16;

    fn process_block(&mut self, block: &[u8]) {
        let n = Self::read_block(block);
        self.process_element(n);
    }

    fn read_block(block: &[u8]) -> Poly1305FieldElement {
        let mut bytes = [0u8; 17];
        bytes[..block.len()].copy_from_slice(block);
        bytes[block.len()] = 1;
        Poly1305FieldElement::from(&bytes)
    }

    fn process_element(&mut self, n: Poly1305FieldElement) {
        self.a += n;
        self.a *= self.r;
    }

    fn create_mac<C>(cipher: &mut C) -> Self
    where
        C: SeekableStreamCipher<Key = [u8; 32]>,
    {
        let mut key = Secret::from([0u8; 32]);
        cipher
            .apply_keystream(key.get_mut())
            .expect("the first keystream block is always available");
        cipher.seek(1);
        Self::new(key.get())
    }

    fn calculate_tag(&mut self, ciphertext: &[u8], aad: Option<&[u8]>) {
        let aad = aad.unwrap_or_default();
        self.update_padded(aad);
        self.update_padded(ciphertext);
        self.update(&(aad.len() as u64).to_le_bytes());
        self.update(&(ciphertext.len() as u64).to_le_bytes());
    }

    fn update_padded(&mut self, message: &[u8]) {
        self.update(message);
        let padding = [0u8; Self::BLOCK_SIZE];
        let padding_size =
            (Self::BLOCK_SIZE - (message.len() % Self::BLOCK_SIZE)) % Self::BLOCK_SIZE;
        self.update(&padding[..padding_size]);
    }
}

#[cfg_attr(target_pointer_width = "32", path = "poly1305/field32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "poly1305/field64.rs")]
mod field;

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    // https://datatracker.ietf.org/doc/html/rfc7539#section-2.5.2

    #[test]
    fn test_poly1305() {
        let key = hex!("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let message = hex!("43727970746f6772617068696320466f72756d2052657365617263682047726f7570");
        let tag = hex!("a8061dc1305136c6c22b8baf0c0127a9");
        let mut mac = Poly1305::new(&key);
        mac.update(&message);
        assert_eq!(mac.finalize(), tag);
    }

    // https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.3

    #[test]
    fn test_poly1305_s_overflow() {
        let key = hex!("02000000000000000000000000000000ffffffffffffffffffffffffffffffff");
        let message = hex!("02000000000000000000000000000000");
        let tag = hex!("03000000000000000000000000000000");
        let mut mac = Poly1305::new(&key);
        mac.update(&message);
        assert_eq!(mac.finalize(), tag);
    }

    #[test]
    fn test_poly1305_sum_above_prime() {
        let key = hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let message = hex!("00000000000000000000000000000000");
        let tag = hex!("faffff13fbffff13fbffff13fbffff13");
        let mut mac = Poly1305::new(&key);
        mac.update(&message);
        assert_eq!(mac.finalize(), tag);
    }
}
