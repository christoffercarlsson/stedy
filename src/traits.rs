pub trait Digest<const BLOCK_SIZE: usize, const DIGEST_SIZE: usize>: Sized {
    fn new() -> Self;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> [u8; DIGEST_SIZE];

    fn finalize_into(self, digest: &mut [u8; DIGEST_SIZE]);
}

pub trait Mac<const DIGEST_SIZE: usize>: Sized {
    fn new(key: &[u8]) -> Self;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> [u8; DIGEST_SIZE];

    fn finalize_into(self, code: &mut [u8; DIGEST_SIZE]);

    fn verify(self, code: &[u8; DIGEST_SIZE]) -> bool;
}
