use {
    crate::{
        block::Block,
        chacha::{ChaCha20, XChaCha20},
        traits::{Authenticator, Digest, Init, KeyInit, Mac, SeekableStreamCipher},
        verify::verify,
    },
    core::ops::{AddAssign, BitAndAssign, Index, IndexMut, MulAssign},
};

pub struct Poly1305 {
    a: Poly1305FieldElement,
    r: Poly1305FieldElement,
    s: Poly1305FieldElement,
    block: Block<{ Self::BLOCK_SIZE }>,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r = Poly1305FieldElement::from(&key[0..16]);
        r &= Poly1305FieldElement::R;
        Self {
            a: Poly1305FieldElement::ZERO,
            r,
            s: Poly1305FieldElement::from(&key[16..32]),
            block: Block::<{ Self::BLOCK_SIZE }>::new(),
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        if let Some((head, tail)) = self.block.blocks(message) {
            self.process_block(&head);
            for block in tail {
                self.process_block(block);
            }
        }
    }

    pub fn finalize_into(self, output: &mut [u8; 16]) {
        output.copy_from_slice(&self.finalize());
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let remaining = self.block.remaining();
        if !remaining.is_empty() {
            let n = Self::read_block(remaining);
            self.process_element(n);
        }
        self.a += self.s;
        self.a.into()
    }
}

impl KeyInit for Poly1305 {
    fn new(key: &[u8]) -> Self {
        let key = <&[u8; 32]>::try_from(key).unwrap();
        Self::new(key)
    }
}

impl Digest for Poly1305 {
    const OUTPUT_SIZE: usize = 16;

    type Output = [u8; Self::OUTPUT_SIZE];

    fn update(&mut self, message: &[u8]) {
        self.update(message);
    }

    fn finalize(self) -> Self::Output {
        self.finalize()
    }

    fn finalize_into(self, output: &mut Self::Output) {
        self.finalize_into(output);
    }
}

impl Mac for Poly1305 {
    fn verify(self, code: &Self::Output) -> bool {
        verify(&self.finalize(), code)
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
        Mac::verify(self, tag)
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
        Mac::verify(self, tag)
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
        Poly1305FieldElement::from(bytes)
    }

    fn process_element(&mut self, n: Poly1305FieldElement) {
        self.a += n;
        self.a *= self.r;
    }

    fn create_mac<C: SeekableStreamCipher>(cipher: &mut C) -> Self {
        let mut key = C::Key::new();
        cipher.apply_keystream(key.as_mut());
        cipher.seek(1);
        <Self as KeyInit>::new(key.as_ref())
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

#[derive(Clone, Copy)]
struct Poly1305FieldElement([u64; 5]);

impl Poly1305FieldElement {
    const MASK: u64 = (1u64 << 26) - 1;
    const R: Self = Self([67108863, 67108611, 67092735, 66076671, 1048575]);
    const ZERO: Self = Self([0; 5]);

    fn reduce(&mut self) {
        let carry = self[4] >> 26;
        self.mask();
        self[0] += carry * 5;
        self[1] += self[0] >> 26;
        self[2] += self[1] >> 26;
        self[0] &= Self::MASK;
        self[1] &= Self::MASK;
    }

    fn carry(&mut self) {
        self[1] += self[0] >> 26;
        self[2] += self[1] >> 26;
        self[3] += self[2] >> 26;
        self[4] += self[3] >> 26;
    }

    fn mask(&mut self) {
        self[0] &= Self::MASK;
        self[1] &= Self::MASK;
        self[2] &= Self::MASK;
        self[3] &= Self::MASK;
        self[4] &= Self::MASK;
    }

    fn canonical(&mut self) {
        let mut reduced = self.clone();
        reduced[0] += 5;
        reduced.carry();
        reduced[4] = reduced[4].wrapping_sub(1 << 26);
        let borrow = reduced[4] >> 63;
        reduced.mask();
        *self = Self::select(&reduced, &self, borrow);
    }

    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        let mask = ((condition != 0) as u64).wrapping_neg();
        Self([
            a[0] & !mask | b[0] & mask,
            a[1] & !mask | b[1] & mask,
            a[2] & !mask | b[2] & mask,
            a[3] & !mask | b[3] & mask,
            a[4] & !mask | b[4] & mask,
        ])
    }
}

impl Index<usize> for Poly1305FieldElement {
    type Output = u64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Poly1305FieldElement {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl AddAssign for Poly1305FieldElement {
    fn add_assign(&mut self, rhs: Self) {
        self[0] += rhs[0];
        self[1] += rhs[1];
        self[2] += rhs[2];
        self[3] += rhs[3];
        self[4] += rhs[4];
        self.carry();
        self.reduce();
    }
}

impl BitAndAssign for Poly1305FieldElement {
    fn bitand_assign(&mut self, rhs: Self) {
        self[0] &= rhs[0];
        self[1] &= rhs[1];
        self[2] &= rhs[2];
        self[3] &= rhs[3];
        self[4] &= rhs[4];
    }
}

impl MulAssign for Poly1305FieldElement {
    fn mul_assign(&mut self, rhs: Self) {
        let mut r = Self::ZERO;
        r[0] += self[0] * rhs[0];
        r[0] += self[4] * rhs[1] * 5;
        r[0] += self[3] * rhs[2] * 5;
        r[0] += self[2] * rhs[3] * 5;
        r[0] += self[1] * rhs[4] * 5;
        r[1] += self[1] * rhs[0];
        r[1] += self[0] * rhs[1];
        r[1] += self[4] * rhs[2] * 5;
        r[1] += self[3] * rhs[3] * 5;
        r[1] += self[2] * rhs[4] * 5;
        r[2] += self[2] * rhs[0];
        r[2] += self[1] * rhs[1];
        r[2] += self[0] * rhs[2];
        r[2] += self[4] * rhs[3] * 5;
        r[2] += self[3] * rhs[4] * 5;
        r[3] += self[3] * rhs[0];
        r[3] += self[2] * rhs[1];
        r[3] += self[1] * rhs[2];
        r[3] += self[0] * rhs[3];
        r[3] += self[4] * rhs[4] * 5;
        r[4] += self[4] * rhs[0];
        r[4] += self[3] * rhs[1];
        r[4] += self[2] * rhs[2];
        r[4] += self[1] * rhs[3];
        r[4] += self[0] * rhs[4];
        r.carry();
        r.reduce();
        *self = r;
    }
}

impl From<[u8; 17]> for Poly1305FieldElement {
    fn from(value: [u8; 17]) -> Self {
        let words = [
            u32::from_le_bytes(value[0..4].try_into().unwrap()) as u64,
            u32::from_le_bytes(value[4..8].try_into().unwrap()) as u64,
            u32::from_le_bytes(value[8..12].try_into().unwrap()) as u64,
            u32::from_le_bytes(value[12..16].try_into().unwrap()) as u64,
            value[16] as u64,
        ];
        let mut fe = Self([
            words[0],
            words[0] >> 26 | (words[1] << 6),
            words[1] >> 20 | (words[2] << 12),
            words[2] >> 14 | (words[3] << 18),
            words[3] >> 8 | (words[4] << 24),
        ]);
        fe.mask();
        fe
    }
}

impl From<&[u8]> for Poly1305FieldElement {
    fn from(value: &[u8]) -> Self {
        let mut bytes = [0u8; 17];
        bytes[0..16].copy_from_slice(&value[0..16]);
        Self::from(bytes)
    }
}

impl From<Poly1305FieldElement> for [u8; 16] {
    fn from(mut fe: Poly1305FieldElement) -> Self {
        fe.canonical();
        let words = [
            (fe[0] | (fe[1] << 26)) as u32,
            (fe[1] >> 6 | (fe[2] << 20)) as u32,
            (fe[2] >> 12 | (fe[3] << 14)) as u32,
            (fe[3] >> 18 | (fe[4] << 8)) as u32,
        ];
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&words[0].to_le_bytes());
        bytes[4..8].copy_from_slice(&words[1].to_le_bytes());
        bytes[8..12].copy_from_slice(&words[2].to_le_bytes());
        bytes[12..16].copy_from_slice(&words[3].to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://datatracker.ietf.org/doc/html/rfc7539#section-2.5.2

    #[test]
    fn test_poly1305() {
        let key = [
            133, 214, 190, 120, 87, 85, 109, 51, 127, 68, 82, 254, 66, 213, 6, 168, 1, 3, 128, 138,
            251, 13, 178, 253, 74, 191, 246, 175, 65, 73, 245, 27,
        ];
        let message = [
            67, 114, 121, 112, 116, 111, 103, 114, 97, 112, 104, 105, 99, 32, 70, 111, 114, 117,
            109, 32, 82, 101, 115, 101, 97, 114, 99, 104, 32, 71, 114, 111, 117, 112,
        ];
        let mut mac = Poly1305::new(&key);
        mac.update(&message);
        let tag = mac.finalize();
        assert_eq!(
            tag,
            [168, 6, 29, 193, 48, 81, 54, 198, 194, 43, 139, 175, 12, 1, 39, 169]
        );
    }
}
