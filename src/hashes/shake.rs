use crate::{
    hashes::{KeccakF1600, Sponge},
    traits::{Init, KeccakPermutation, Xof, XofReader},
};

#[derive(Clone)]
pub struct Shake128(Shake<168, KeccakF1600>);

impl Shake128 {
    pub fn digest(message: &[u8], output: &mut [u8]) {
        Shake::<168, KeccakF1600>::digest(message, output);
    }

    pub fn new() -> Self {
        Self(Shake::<168, KeccakF1600>::new())
    }

    pub fn update(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    pub fn finalize_into(self, output: &mut [u8]) {
        self.0.finalize_into(output);
    }

    pub fn finalize_xof(self) -> Shake128Reader {
        Shake128Reader(self.0.finalize_xof())
    }
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Init for Shake128 {
    fn new() -> Self {
        Self::new()
    }
}

impl Xof for Shake128 {
    type Block = [u8; 168];
    type Reader = Shake128Reader;

    fn digest(message: &[u8], output: &mut [u8]) {
        Self::digest(message, output);
    }

    fn update(&mut self, message: &[u8]) {
        self.update(message);
    }

    fn finalize_into(self, output: &mut [u8]) {
        self.finalize_into(output);
    }

    fn finalize_xof(self) -> Self::Reader {
        self.finalize_xof()
    }
}

#[derive(Clone)]
pub struct Shake128Reader(ShakeReader<168, KeccakF1600>);

impl Shake128Reader {
    pub fn read(&mut self, output: &mut [u8]) {
        self.0.read(output);
    }
}

impl XofReader for Shake128Reader {
    fn read(&mut self, output: &mut [u8]) {
        self.read(output);
    }
}

#[derive(Clone)]
pub struct Shake256(Shake<136, KeccakF1600>);

impl Shake256 {
    pub fn digest(message: &[u8], output: &mut [u8]) {
        Shake::<136, KeccakF1600>::digest(message, output);
    }

    pub fn new() -> Self {
        Self(Shake::<136, KeccakF1600>::new())
    }

    pub fn update(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    pub fn finalize_into(self, output: &mut [u8]) {
        self.0.finalize_into(output);
    }

    pub fn finalize_xof(self) -> Shake256Reader {
        Shake256Reader(self.0.finalize_xof())
    }
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Init for Shake256 {
    fn new() -> Self {
        Self::new()
    }
}

impl Xof for Shake256 {
    type Block = [u8; 136];
    type Reader = Shake256Reader;

    fn digest(message: &[u8], output: &mut [u8]) {
        Self::digest(message, output);
    }

    fn update(&mut self, message: &[u8]) {
        self.update(message);
    }

    fn finalize_into(self, output: &mut [u8]) {
        self.finalize_into(output);
    }

    fn finalize_xof(self) -> Self::Reader {
        self.finalize_xof()
    }
}

#[derive(Clone)]
pub struct Shake256Reader(ShakeReader<136, KeccakF1600>);

impl Shake256Reader {
    pub fn read(&mut self, output: &mut [u8]) {
        self.0.read(output);
    }
}

impl XofReader for Shake256Reader {
    fn read(&mut self, output: &mut [u8]) {
        self.read(output);
    }
}

pub struct Shake128With<P>(Shake<168, P>)
where
    P: KeccakPermutation;

impl<P> Clone for Shake128With<P>
where
    P: KeccakPermutation,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P> Shake128With<P>
where
    P: KeccakPermutation,
{
    pub fn digest(message: &[u8], output: &mut [u8]) {
        Shake::<168, P>::digest(message, output);
    }

    pub fn new() -> Self {
        Self(Shake::<168, P>::new())
    }

    pub fn update(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    pub fn finalize_into(self, output: &mut [u8]) {
        self.0.finalize_into(output);
    }

    pub fn finalize_xof(self) -> Shake128ReaderWith<P> {
        Shake128ReaderWith(self.0.finalize_xof())
    }
}

impl<P> Default for Shake128With<P>
where
    P: KeccakPermutation,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<P> Init for Shake128With<P>
where
    P: KeccakPermutation,
{
    fn new() -> Self {
        Self::new()
    }
}

impl<P> Xof for Shake128With<P>
where
    P: KeccakPermutation,
{
    type Block = [u8; 168];
    type Reader = Shake128ReaderWith<P>;

    fn digest(message: &[u8], output: &mut [u8]) {
        Self::digest(message, output);
    }

    fn update(&mut self, message: &[u8]) {
        self.update(message);
    }

    fn finalize_into(self, output: &mut [u8]) {
        self.finalize_into(output);
    }

    fn finalize_xof(self) -> Self::Reader {
        self.finalize_xof()
    }
}

pub struct Shake128ReaderWith<P>(ShakeReader<168, P>)
where
    P: KeccakPermutation;

impl<P> Clone for Shake128ReaderWith<P>
where
    P: KeccakPermutation,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P> Shake128ReaderWith<P>
where
    P: KeccakPermutation,
{
    pub fn read(&mut self, output: &mut [u8]) {
        self.0.read(output);
    }
}

impl<P> XofReader for Shake128ReaderWith<P>
where
    P: KeccakPermutation,
{
    fn read(&mut self, output: &mut [u8]) {
        self.read(output);
    }
}

pub struct Shake256With<P>(Shake<136, P>)
where
    P: KeccakPermutation;

impl<P> Clone for Shake256With<P>
where
    P: KeccakPermutation,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P> Shake256With<P>
where
    P: KeccakPermutation,
{
    pub fn digest(message: &[u8], output: &mut [u8]) {
        Shake::<136, P>::digest(message, output);
    }

    pub fn new() -> Self {
        Self(Shake::<136, P>::new())
    }

    pub fn update(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    pub fn finalize_into(self, output: &mut [u8]) {
        self.0.finalize_into(output);
    }

    pub fn finalize_xof(self) -> Shake256ReaderWith<P> {
        Shake256ReaderWith(self.0.finalize_xof())
    }
}

impl<P> Default for Shake256With<P>
where
    P: KeccakPermutation,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<P> Init for Shake256With<P>
where
    P: KeccakPermutation,
{
    fn new() -> Self {
        Self::new()
    }
}

impl<P> Xof for Shake256With<P>
where
    P: KeccakPermutation,
{
    type Block = [u8; 136];
    type Reader = Shake256ReaderWith<P>;

    fn digest(message: &[u8], output: &mut [u8]) {
        Self::digest(message, output);
    }

    fn update(&mut self, message: &[u8]) {
        self.update(message);
    }

    fn finalize_into(self, output: &mut [u8]) {
        self.finalize_into(output);
    }

    fn finalize_xof(self) -> Self::Reader {
        self.finalize_xof()
    }
}

pub struct Shake256ReaderWith<P>(ShakeReader<136, P>)
where
    P: KeccakPermutation;

impl<P> Clone for Shake256ReaderWith<P>
where
    P: KeccakPermutation,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P> Shake256ReaderWith<P>
where
    P: KeccakPermutation,
{
    pub fn read(&mut self, output: &mut [u8]) {
        self.0.read(output);
    }
}

impl<P> XofReader for Shake256ReaderWith<P>
where
    P: KeccakPermutation,
{
    fn read(&mut self, output: &mut [u8]) {
        self.read(output);
    }
}

struct Shake<const RATE: usize, P>(Sponge<RATE, P>)
where
    P: KeccakPermutation;

impl<const RATE: usize, P> Clone for Shake<RATE, P>
where
    P: KeccakPermutation,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<const RATE: usize, P> Shake<RATE, P>
where
    P: KeccakPermutation,
{
    const DOMAIN: u8 = 0x1f;

    pub(crate) fn digest(message: &[u8], output: &mut [u8]) {
        let mut hasher = Self::new();
        hasher.update(message);
        hasher.finalize_into(output);
    }

    pub(crate) fn new() -> Self {
        const {
            assert!(
                RATE == 168 || RATE == 136,
                "SHAKE rates are 168 or 136 bytes"
            );
        }
        Self(Sponge::<RATE, P>::new())
    }

    pub(crate) fn update(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    pub(crate) fn finalize_into(mut self, output: &mut [u8]) {
        self.0.pad(Self::DOMAIN);
        self.0.squeeze(output);
    }

    pub(crate) fn finalize_xof(mut self) -> ShakeReader<RATE, P> {
        self.0.pad(Self::DOMAIN);
        ShakeReader {
            sponge: self.0,
            offset: 0,
        }
    }
}

struct ShakeReader<const RATE: usize, P>
where
    P: KeccakPermutation,
{
    sponge: Sponge<RATE, P>,
    offset: usize,
}

impl<const RATE: usize, P> Clone for ShakeReader<RATE, P>
where
    P: KeccakPermutation,
{
    fn clone(&self) -> Self {
        Self {
            sponge: self.sponge.clone(),
            offset: self.offset,
        }
    }
}

impl<const RATE: usize, P> ShakeReader<RATE, P>
where
    P: KeccakPermutation,
{
    pub(crate) fn read(&mut self, output: &mut [u8]) {
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
