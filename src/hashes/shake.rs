use crate::hashes::keccak::Sponge;

pub type Shake128 = Shake<168>;
pub type Shake256 = Shake<136>;

#[derive(Clone)]
pub struct Shake<const RATE: usize>(Sponge<RATE>);

impl<const RATE: usize> Shake<RATE> {
    const DOMAIN: u8 = 0x1f;

    pub fn digest(message: &[u8], output: &mut [u8]) {
        let mut hasher = Self::new();
        hasher.update(message);
        hasher.finalize_into(output);
    }

    pub fn new() -> Self {
        Self(Sponge::<RATE>::new())
    }

    pub fn update(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    pub fn finalize_into(mut self, output: &mut [u8]) {
        self.0.pad(Self::DOMAIN);
        self.0.squeeze(output);
    }

    pub fn finalize_xof(mut self) -> ShakeReader<RATE> {
        self.0.pad(Self::DOMAIN);
        ShakeReader {
            sponge: self.0,
            offset: 0,
        }
    }
}

impl<const RATE: usize> Default for Shake<RATE> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct ShakeReader<const RATE: usize> {
    sponge: Sponge<RATE>,
    offset: usize,
}

impl<const RATE: usize> ShakeReader<RATE> {
    pub fn read(&mut self, output: &mut [u8]) {
        let mut output = output;
        while !output.is_empty() {
            if self.offset == RATE {
                self.sponge.permute();
                self.offset = 0;
            }
            let take = output.len().min(RATE - self.offset);
            let (head, tail) = output.split_at_mut(take);
            self.sponge.read(self.offset, head);
            self.offset += take;
            output = tail;
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

    #[test]
    fn test_shake128_0bits() {
        let mut digest = [0u8; 32];
        Shake128::digest(b"", &mut digest);
        assert_eq!(
            digest,
            hex!("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
        );
    }

    #[test]
    fn test_shake128_24bits() {
        let mut digest = [0u8; 32];
        Shake128::digest(b"abc", &mut digest);
        assert_eq!(
            digest,
            hex!("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8")
        );
    }

    #[test]
    fn test_shake256_0bits() {
        let mut digest = [0u8; 32];
        Shake256::digest(b"", &mut digest);
        assert_eq!(
            digest,
            hex!("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
        );
    }

    #[test]
    fn test_shake256_24bits() {
        let mut digest = [0u8; 32];
        Shake256::digest(b"abc", &mut digest);
        assert_eq!(
            digest,
            hex!("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739")
        );
    }
}
