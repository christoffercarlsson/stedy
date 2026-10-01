use {
    crate::{
        traits::{Digest, KeyInit, Mac},
        utils::{verify, Block, Secret},
    },
    core::hash::Hasher,
};

pub type SipHash13 = SipHash<1, 3, 8>;
pub type SipHash24 = SipHash<2, 4, 8>;
pub type SipHash48 = SipHash<4, 8, 8>;
pub type SipHashX13 = SipHash<1, 3, 16>;
pub type SipHashX24 = SipHash<2, 4, 16>;
pub type SipHashX48 = SipHash<4, 8, 16>;

#[derive(Clone)]
pub struct SipHash<const C: usize, const D: usize, const N: usize> {
    v: Secret<[u64; 4]>,
    block: Block<8>,
    length: u8,
}

impl<const C: usize, const D: usize, const N: usize> SipHash<C, D, N> {
    pub fn new(key: &[u8; 16]) -> Self {
        const {
            assert!(N == 8 || N == 16, "SipHash outputs are 64 or 128 bits");
        }
        let (k0, k1) = key.split_at(8);
        let k0 = u64::from_le_bytes(k0.try_into().expect("Key half is 8 bytes"));
        let k1 = u64::from_le_bytes(k1.try_into().expect("Key half is 8 bytes"));
        let mut v = [
            k0 ^ 0x736f6d6570736575,
            k1 ^ 0x646f72616e646f6d,
            k0 ^ 0x6c7967656e657261,
            k1 ^ 0x7465646279746573,
        ];
        if N == 16 {
            v[1] ^= 0xee;
        }
        Self {
            v: Secret::from(v),
            block: Block::<8>::new(),
            length: 0,
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        self.length = self.length.wrapping_add(message.len() as u8);
        if let Some((head, tail)) = self.block.blocks(message) {
            self.compress(u64::from_le_bytes(head));
            for block in tail {
                self.compress(u64::from_le_bytes(*block));
            }
        }
    }

    pub fn finalize_into(mut self, code: &mut [u8]) {
        let (mut block, _) = self.block.remaining_block().unwrap_or(([0u8; 8], 0));
        block[7] = self.length;
        self.compress(u64::from_le_bytes(block));
        let v = self.v.get_mut();
        v[2] ^= if N == 16 { 0xee } else { 0xff };
        Self::rounds(v, D);
        let mut output = [0u8; N];
        output[..8].copy_from_slice(&(v[0] ^ v[1] ^ v[2] ^ v[3]).to_le_bytes());
        if N == 16 {
            v[1] ^= 0xdd;
            Self::rounds(v, D);
            output[8..].copy_from_slice(&(v[0] ^ v[1] ^ v[2] ^ v[3]).to_le_bytes());
        }
        let size = code.len().min(N);
        code[..size].copy_from_slice(&output[..size]);
    }

    pub fn finalize(self) -> [u8; N] {
        let mut code = [0u8; N];
        self.finalize_into(&mut code);
        code
    }

    pub fn verify(self, code: &[u8; N]) -> bool {
        verify(&self.finalize(), code)
    }

    fn compress(&mut self, m: u64) {
        let v = self.v.get_mut();
        v[3] ^= m;
        Self::rounds(v, C);
        v[0] ^= m;
    }

    fn rounds(v: &mut [u64; 4], count: usize) {
        for _ in 0..count {
            v[0] = v[0].wrapping_add(v[1]);
            v[1] = v[1].rotate_left(13);
            v[1] ^= v[0];
            v[0] = v[0].rotate_left(32);
            v[2] = v[2].wrapping_add(v[3]);
            v[3] = v[3].rotate_left(16);
            v[3] ^= v[2];
            v[0] = v[0].wrapping_add(v[3]);
            v[3] = v[3].rotate_left(21);
            v[3] ^= v[0];
            v[2] = v[2].wrapping_add(v[1]);
            v[1] = v[1].rotate_left(17);
            v[1] ^= v[2];
            v[2] = v[2].rotate_left(32);
        }
    }
}

impl<const C: usize, const D: usize, const N: usize> KeyInit for SipHash<C, D, N> {
    fn new(key: &[u8]) -> Self {
        let key = <&[u8; 16]>::try_from(key).expect("SipHash keys are always 16 bytes");
        Self::new(key)
    }
}

impl<const C: usize, const D: usize, const N: usize> Digest for SipHash<C, D, N> {
    const OUTPUT_SIZE: usize = N;

    type Output = [u8; N];

    fn update(&mut self, message: &[u8]) {
        self.update(message);
    }

    fn finalize(self) -> Self::Output {
        self.finalize()
    }

    fn finalize_into(self, output: &mut [u8]) {
        self.finalize_into(output);
    }
}

impl<const C: usize, const D: usize, const N: usize> Mac for SipHash<C, D, N> {
    fn verify(self, code: &Self::Output) -> bool {
        self.verify(code)
    }
}

impl<const C: usize, const D: usize> Hasher for SipHash<C, D, 8> {
    fn write(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }

    fn finish(&self) -> u64 {
        u64::from_le_bytes(self.clone().finalize())
    }
}

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    // https://github.com/veorq/SipHash/blob/master/vectors.h

    #[test]
    fn test_siphash24_0_bytes() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let mac = SipHash24::new(&key);
        assert_eq!(mac.finalize(), hex!("310e0edd47db6f72"));
    }

    #[test]
    fn test_siphash24_1_byte() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let message = hex!("00");
        let mut mac = SipHash24::new(&key);
        mac.update(&message);
        assert_eq!(mac.finalize(), hex!("fd67dc93c539f874"));
    }

    #[test]
    fn test_siphash24_7_bytes() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let message = hex!("00010203040506");
        let mut mac = SipHash24::new(&key);
        mac.update(&message);
        assert_eq!(mac.finalize(), hex!("37d1018bf50002ab"));
    }

    #[test]
    fn test_siphash24_8_bytes() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let message = hex!("0001020304050607");
        let mut mac = SipHash24::new(&key);
        mac.update(&message);
        assert_eq!(mac.finalize(), hex!("6224939a79f5f593"));
    }

    #[test]
    fn test_siphash24_9_bytes() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let message = hex!("000102030405060708");
        let mut mac = SipHash24::new(&key);
        mac.update(&message);
        assert_eq!(mac.finalize(), hex!("b0e4a90bdf82009e"));
    }

    #[test]
    fn test_siphash24_15_bytes() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let message = hex!("000102030405060708090a0b0c0d0e");
        let code = hex!("e545be4961ca29a1");
        let mut mac = SipHash24::new(&key);
        mac.update(&message);
        assert_eq!(mac.finalize(), code);
        let mut mac = SipHash24::new(&key);
        mac.update(&message);
        assert!(mac.verify(&code));
        let mut mac = SipHash24::new(&key);
        mac.update(&message);
        assert!(!mac.verify(&hex!("e545be4961ca29a0")));
    }

    #[test]
    fn test_siphash24_63_bytes() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let message = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e");
        let mut mac = SipHash24::new(&key);
        mac.update(&message[..5]);
        mac.update(&message[5..20]);
        mac.update(&message[20..]);
        assert_eq!(mac.finalize(), hex!("724506eb4c328a95"));
    }

    #[test]
    fn test_siphash24_hasher() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let mut hasher = SipHash24::new(&key);
        hasher.write(&hex!("000102030405060708090a0b0c0d0e"));
        assert_eq!(
            hasher.finish(),
            u64::from_le_bytes(hex!("e545be4961ca29a1"))
        );
    }

    #[test]
    fn test_siphashx24_0_bytes() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let mac = SipHashX24::new(&key);
        assert_eq!(mac.finalize(), hex!("a3817f04ba25a8e66df67214c7550293"));
    }

    #[test]
    fn test_siphashx24_15_bytes() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let message = hex!("000102030405060708090a0b0c0d0e");
        let mut mac = SipHashX24::new(&key);
        mac.update(&message);
        assert_eq!(mac.finalize(), hex!("5493e99933b0a8117e08ec0f97cfc3d9"));
    }

    #[test]
    fn test_siphashx24_63_bytes() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let message = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e");
        let mut mac = SipHashX24::new(&key);
        mac.update(&message);
        assert_eq!(mac.finalize(), hex!("5150d1772f50834a503e069a973fbd7c"));
    }
}
