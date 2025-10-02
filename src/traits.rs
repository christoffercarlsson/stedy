pub trait Hasher<const BLOCK_SIZE: usize, const DIGEST_SIZE: usize>: Sized {
    fn new() -> Self;

    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> [u8; DIGEST_SIZE];

    fn finalize_into(self, digest: &mut [u8; DIGEST_SIZE]);
}
