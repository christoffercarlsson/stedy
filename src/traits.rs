#[allow(private_bounds)]
pub trait ByteArray: Sealed + Init + AsRef<[u8]> + AsMut<[u8]> + 'static {}

pub trait Init {
    fn new() -> Self;
}

pub trait KeyInit {
    fn new(key: &[u8]) -> Self;
}

pub trait Digest {
    type Output: ByteArray;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> Self::Output;

    fn finalize_into(self, output: &mut Self::Output);
}

pub trait Hasher: Init + Digest {}

pub trait Mac: KeyInit + Digest {
    fn verify(self, code: &Self::Output) -> bool;
}

pub trait Csprng {
    type Seed: ByteArray;

    fn new(seed: &Self::Seed) -> Self;

    fn fill(&mut self, bytes: &mut [u8]);

    fn next_u32(&mut self) -> u32;

    fn next_u64(&mut self) -> u64;
}

trait Sealed {}

impl<const N: usize> Sealed for [u8; N] {}

impl<const N: usize> ByteArray for [u8; N] {}

impl<const N: usize> Init for [u8; N] {
    fn new() -> Self {
        [0u8; N]
    }
}

impl<T: Init + Digest> Hasher for T {}
