use crate::{block::Block, field::Poly1305 as Poly1305Field};

const R: [u8; 16] = [
    255, 255, 255, 15, 252, 255, 255, 15, 252, 255, 255, 15, 252, 255, 255, 15,
];

pub struct Poly1305 {
    a: Poly1305Field,
    r: Poly1305Field,
    s: Poly1305Field,
    block: Block<16>,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r = Poly1305Field::from(&key[0..16]);
        r &= Poly1305Field::from(&R);
        Self {
            a: Poly1305Field::zero(),
            r,
            s: Poly1305Field::from(&key[16..32]),
            block: Block::<16>::new(),
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        let (head, tail) = self.block.blocks(message);
        if let Some(head) = head {
            self.process_block(&head);
        }
        for (begin, end) in tail {
            self.process_block(&message[begin..end]);
        }
    }

    pub fn update_padded(&mut self, message: &[u8]) {
        self.update(message);
        let padding = [0u8; 16];
        let padding_size = (16 - (message.len() % 16)) % 16;
        self.update(&padding[..padding_size]);
    }

    fn process_block(&mut self, block: &[u8]) {
        let mut bytes = [0u8; 17];
        bytes[..block.len()].copy_from_slice(block);
        bytes[block.len()] = 1;
        self.a += Poly1305Field::from(&bytes);
        self.a *= self.r;
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let block = self.block;
        let remaining = block.remaining();
        if !remaining.is_empty() {
            self.process_block(remaining);
        }
        self.a += self.s;
        self.a.into()
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
