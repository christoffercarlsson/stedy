pub trait Init {
    fn new() -> Self;
}

pub trait KeyInit {
    fn new(key: &[u8]) -> Self;
}

pub trait Digest<const OUTPUT_SIZE: usize>: Sized {
    fn update(&mut self, message: &[u8]);

    fn finalize(self) -> [u8; OUTPUT_SIZE];

    fn finalize_into(self, output: &mut [u8; OUTPUT_SIZE]);
}

pub trait Hasher<const BLOCK_SIZE: usize, const OUTPUT_SIZE: usize>:
    Init + Digest<OUTPUT_SIZE>
{
}

pub trait Mac<const OUTPUT_SIZE: usize>: KeyInit + Digest<OUTPUT_SIZE> {
    #[allow(dead_code)]
    fn verify(self, code: &[u8; OUTPUT_SIZE]) -> bool;
}
