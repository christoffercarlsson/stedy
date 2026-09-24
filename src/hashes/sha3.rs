use crate::{
    hashes::keccak::Sponge,
    traits::{Digest, Hasher, Init},
};

pub type Sha3_224 = Sha3<144, 28>;
pub type Sha3_256 = Sha3<136, 32>;
pub type Sha3_384 = Sha3<104, 48>;
pub type Sha3_512 = Sha3<72, 64>;

#[derive(Clone)]
pub struct Sha3<const RATE: usize, const N: usize>(Sponge<RATE>);

impl<const RATE: usize, const N: usize> Sha3<RATE, N> {
    const DOMAIN: u8 = 0x06;
    const WIDTH: usize = 200;

    pub fn digest(message: &[u8]) -> [u8; N] {
        let mut hasher = Self::new();
        hasher.update(message);
        hasher.finalize()
    }

    pub fn new() -> Self {
        const {
            assert!(
                RATE + 2 * N == Self::WIDTH,
                "Rate and digest size are compatible"
            );
        }
        Self(Sponge::<RATE>::new())
    }

    pub fn update(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    pub fn finalize_into(mut self, digest: &mut [u8]) {
        self.0.pad(Self::DOMAIN);
        let size = digest.len().min(N);
        self.0.squeeze(&mut digest[..size]);
    }

    pub fn finalize(self) -> [u8; N] {
        let mut digest = [0u8; N];
        self.finalize_into(&mut digest);
        digest
    }
}

impl<const RATE: usize, const N: usize> Default for Sha3<RATE, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const RATE: usize, const N: usize> Init for Sha3<RATE, N> {
    fn new() -> Self {
        Self::new()
    }
}

impl<const RATE: usize, const N: usize> Digest for Sha3<RATE, N> {
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

macro_rules! impl_hasher {
    ($($t:ty => $rate:literal),*) => {
        $(
            impl Hasher for $t {
                const BLOCK_SIZE: usize = $rate;

                type Block = [u8; $rate];

                fn digest(message: &[u8]) -> Self::Output {
                    Self::digest(message)
                }
            }
        )*
    };
}

impl_hasher!(Sha3_224 => 144, Sha3_256 => 136, Sha3_384 => 104, Sha3_512 => 72);

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    // https://www.di-mgt.com.au/sha_testvectors.html

    #[test]
    fn test_sha3_224_0bits() {
        let digest = Sha3_224::digest(b"");
        assert_eq!(
            digest,
            hex!("6b4e03423667dbb7 3b6e15454f0eb1ab d4597f9a1b078e3f 5b5a6bc7")
        );
    }

    #[test]
    fn test_sha3_224_24bits() {
        let digest = Sha3_224::digest(b"abc");
        assert_eq!(
            digest,
            hex!("e642824c3f8cf24a d09234ee7d3c766f c9a3a5168d0c94ad 73b46fdf")
        );
    }

    #[test]
    fn test_sha3_224_448bits() {
        let digest = Sha3_224::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            digest,
            hex!("8a24108b154ada21 c9fd5574494479ba 5c7e7ab76ef264ea d0fcce33")
        );
    }

    #[test]
    fn test_sha3_224_896bits() {
        let digest = Sha3_224::digest(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        assert_eq!(
            digest,
            hex!("543e6868e1666c1a 643630df77367ae5 a62a85070a51c14c bf665cbc")
        );
    }

    #[test]
    fn test_sha3_224_1m() {
        let mut hasher = Sha3_224::new();
        for _ in 0..1000000 {
            hasher.update(b"a");
        }
        let digest = hasher.finalize();
        assert_eq!(
            digest,
            hex!("d69335b93325192e 516a912e6d19a15c b51c6ed5c15243e7 a7fd653c")
        );
    }

    #[test]
    fn test_sha3_256_0bits() {
        let digest = Sha3_256::digest(b"");
        assert_eq!(
            digest,
            hex!("a7ffc6f8bf1ed766 51c14756a061d662 f580ff4de43b49fa 82d80a4b80f8434a")
        );
    }

    #[test]
    fn test_sha3_256_24bits() {
        let digest = Sha3_256::digest(b"abc");
        assert_eq!(
            digest,
            hex!("3a985da74fe225b2 045c172d6bd390bd 855f086e3e9d525b 46bfe24511431532")
        );
    }

    #[test]
    fn test_sha3_256_448bits() {
        let digest = Sha3_256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            digest,
            hex!("41c0dba2a9d62408 49100376a8235e2c 82e1b9998a999e21 db32dd97496d3376")
        );
    }

    #[test]
    fn test_sha3_256_896bits() {
        let digest = Sha3_256::digest(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        assert_eq!(
            digest,
            hex!("916f6061fe879741 ca6469b43971dfdb 28b1a32dc36cb325 4e812be27aad1d18")
        );
    }

    #[test]
    fn test_sha3_256_1m() {
        let mut hasher = Sha3_256::new();
        for _ in 0..1000000 {
            hasher.update(b"a");
        }
        let digest = hasher.finalize();
        assert_eq!(
            digest,
            hex!("5c8875ae474a3634 ba4fd55ec85bffd6 61f32aca75c6d699 d0cdcb6c115891c1")
        );
    }

    #[test]
    fn test_sha3_384_0bits() {
        let digest = Sha3_384::digest(b"");
        assert_eq!(
            digest,
            hex!("0c63a75b845e4f7d 01107d852e4c2485 c51a50aaaa94fc61 995e71bbee983a2a c3713831264adb47 fb6bd1e058d5f004")
        );
    }

    #[test]
    fn test_sha3_384_24bits() {
        let digest = Sha3_384::digest(b"abc");
        assert_eq!(
            digest,
            hex!("ec01498288516fc9 26459f58e2c6ad8d f9b473cb0fc08c25 96da7cf0e49be4b2 98d88cea927ac7f5 39f1edf228376d25")
        );
    }

    #[test]
    fn test_sha3_384_448bits() {
        let digest = Sha3_384::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            digest,
            hex!("991c665755eb3a4b 6bbdfb75c78a492e 8c56a22c5c4d7e42 9bfdbc32b9d4ad5a a04a1f076e62fea1 9eef51acd0657c22")
        );
    }

    #[test]
    fn test_sha3_384_896bits() {
        let digest = Sha3_384::digest(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        assert_eq!(
            digest,
            hex!("79407d3b5916b59c 3e30b09822974791 c313fb9ecc849e40 6f23592d04f625dc 8c709b98b43b3852 b337216179aa7fc7")
        );
    }

    #[test]
    fn test_sha3_384_1m() {
        let mut hasher = Sha3_384::new();
        for _ in 0..1000000 {
            hasher.update(b"a");
        }
        let digest = hasher.finalize();
        assert_eq!(
            digest,
            hex!("eee9e24d78c18553 37983451df97c8ad 9eedf256c6334f8e 948d252d5e0e7684 7aa0774ddb90a842 190d2c558b4b8340")
        );
    }

    #[test]
    fn test_sha3_512_0bits() {
        let digest = Sha3_512::digest(b"");
        assert_eq!(
            digest,
            hex!("a69f73cca23a9ac5 c8b567dc185a756e 97c982164fe25859 e0d1dcc1475c80a6 15b2123af1f5f94c 11e3e9402c3ac558 f500199d95b6d3e3 01758586281dcd26")
        );
    }

    #[test]
    fn test_sha3_512_24bits() {
        let digest = Sha3_512::digest(b"abc");
        assert_eq!(
            digest,
            hex!("b751850b1a57168a 5693cd924b6b096e 08f621827444f70d 884f5d0240d2712e 10e116e9192af3c9 1a7ec57647e39340 57340b4cf408d5a5 6592f8274eec53f0")
        );
    }

    #[test]
    fn test_sha3_512_448bits() {
        let digest = Sha3_512::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            digest,
            hex!("04a371e84ecfb5b8 b77cb48610fca818 2dd457ce6f326a0f d3d7ec2f1e91636d ee691fbe0c985302 ba1b0d8dc78c0863 46b533b49c030d99 a27daf1139d6e75e")
        );
    }

    #[test]
    fn test_sha3_512_896bits() {
        let digest = Sha3_512::digest(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        assert_eq!(
            digest,
            hex!("afebb2ef542e6579 c50cad06d2e578f9 f8dd6881d7dc824d 26360feebf18a4fa 73e3261122948efc fd492e74e82e2189 ed0fb440d187f382 270cb455f21dd185")
        );
    }

    #[test]
    fn test_sha3_512_1m() {
        let mut hasher = Sha3_512::new();
        for _ in 0..1000000 {
            hasher.update(b"a");
        }
        let digest = hasher.finalize();
        assert_eq!(
            digest,
            hex!("3c3a876da14034ab 60627c077bb98f7e 120a2a5370212dff b3385a18d4f38859 ed311d0a9d5141ce 9cc5c66ee689b266 a8aa18ace8282a0e 0db596c90b0a7b87")
        );
    }
}
