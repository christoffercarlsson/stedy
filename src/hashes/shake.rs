use crate::{
    hashes::keccak::{KeccakF1600, Sponge},
    traits::{Digest, Hasher, Init, KeccakPermutation, Xof, XofReader},
};

pub type Shake128With<P> = Shake<168, P>;
pub type Shake256With<P> = Shake<136, P>;
pub type Shake128DigestWith<const N: usize, P> = ShakeDigest<168, N, P>;
pub type Shake256DigestWith<const N: usize, P> = ShakeDigest<136, N, P>;

pub type Shake128 = Shake128With<KeccakF1600>;
pub type Shake256 = Shake256With<KeccakF1600>;
pub type Shake128Digest<const N: usize> = Shake128DigestWith<N, KeccakF1600>;
pub type Shake256Digest<const N: usize> = Shake256DigestWith<N, KeccakF1600>;

impl<const RATE: usize, P: KeccakPermutation> Init for Shake<RATE, P> {
    fn new() -> Self {
        Self::new()
    }
}

impl<const RATE: usize, P: KeccakPermutation> Xof for Shake<RATE, P> {
    type Reader = ShakeReader<RATE, P>;

    fn digest(message: &[u8], output: &mut [u8]) {
        Self::digest(message, output);
    }

    fn update(&mut self, message: &[u8]) {
        self.update(message);
    }

    fn finalize_into(self, output: &mut [u8]) {
        self.finalize_into(output);
    }

    fn finalize_xof(self) -> ShakeReader<RATE, P> {
        self.finalize_xof()
    }
}

impl<const RATE: usize, P: KeccakPermutation> XofReader for ShakeReader<RATE, P> {
    fn read(&mut self, output: &mut [u8]) {
        self.read(output);
    }
}

pub struct Shake<const RATE: usize, P: KeccakPermutation>(Sponge<RATE, P>);

impl<const RATE: usize, P: KeccakPermutation> Clone for Shake<RATE, P> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<const RATE: usize, P: KeccakPermutation> Shake<RATE, P> {
    const DOMAIN: u8 = 0x1f;

    pub fn digest(message: &[u8], output: &mut [u8]) {
        let mut hasher = Self::new();
        hasher.update(message);
        hasher.finalize_into(output);
    }

    pub fn new() -> Self {
        const {
            assert!(
                RATE == 168 || RATE == 136,
                "SHAKE rates are 168 or 136 bytes"
            )
        }
        Self(Sponge::<RATE, P>::new())
    }

    pub fn update(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    pub fn finalize_into(mut self, output: &mut [u8]) {
        self.0.pad(Self::DOMAIN);
        self.0.squeeze(output);
    }

    pub fn finalize_xof(mut self) -> ShakeReader<RATE, P> {
        self.0.pad(Self::DOMAIN);
        ShakeReader {
            sponge: self.0,
            offset: 0,
        }
    }
}

impl<const RATE: usize, P: KeccakPermutation> Default for Shake<RATE, P> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ShakeDigest<const RATE: usize, const N: usize, P: KeccakPermutation>(Shake<RATE, P>);

impl<const RATE: usize, const N: usize, P: KeccakPermutation> Clone for ShakeDigest<RATE, N, P> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<const RATE: usize, const N: usize, P: KeccakPermutation> ShakeDigest<RATE, N, P> {
    pub fn digest(message: &[u8]) -> [u8; N] {
        let mut hasher = Self::new();
        hasher.update(message);
        hasher.finalize()
    }

    pub fn new() -> Self {
        const { assert!(N >= 1, "SHAKE digests are at least 1 byte") }
        Self(Shake::<RATE, P>::new())
    }

    pub fn update(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    pub fn finalize_into(self, digest: &mut [u8]) {
        let size = digest.len().min(N);
        self.0.finalize_into(&mut digest[..size]);
    }

    pub fn finalize(self) -> [u8; N] {
        let mut digest = [0u8; N];
        self.finalize_into(&mut digest);
        digest
    }
}

impl<const RATE: usize, const N: usize, P: KeccakPermutation> Default for ShakeDigest<RATE, N, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const RATE: usize, const N: usize, P: KeccakPermutation> Init for ShakeDigest<RATE, N, P> {
    fn new() -> Self {
        Self::new()
    }
}

impl<const RATE: usize, const N: usize, P: KeccakPermutation> Digest for ShakeDigest<RATE, N, P> {
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

impl<const RATE: usize, const N: usize, P: KeccakPermutation> Hasher for ShakeDigest<RATE, N, P> {
    const BLOCK_SIZE: usize = RATE;

    type Block = [u8; RATE];

    fn digest(message: &[u8]) -> Self::Output {
        Self::digest(message)
    }
}

pub struct ShakeReader<const RATE: usize, P: KeccakPermutation> {
    sponge: Sponge<RATE, P>,
    offset: usize,
}

impl<const RATE: usize, P: KeccakPermutation> Clone for ShakeReader<RATE, P> {
    fn clone(&self) -> Self {
        Self {
            sponge: self.sponge.clone(),
            offset: self.offset,
        }
    }
}

impl<const RATE: usize, P: KeccakPermutation> ShakeReader<RATE, P> {
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
