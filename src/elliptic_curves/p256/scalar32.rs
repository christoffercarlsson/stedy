use crate::{elliptic_curves::Montgomery, traits::MontgomeryParams};

#[derive(Clone, Copy)]
pub struct ScalarP256Params;

impl MontgomeryParams<10> for ScalarP256Params {
    const BITS: u32 = 26;
    const TOP_BITS: u32 = 22;
    const MOD: [u64; 10] = [
        6497617, 41070783, 32001851, 45522014, 62711546, 67108863, 67108863, 1023, 67043328,
        4194303,
    ];
    const R: [u64; 10] = [
        30255856, 13956110, 24841286, 9845272, 3248213, 1, 0, 67092480, 1048575, 0,
    ];
    const R2: [u64; 10] = [
        40747962, 24314746, 64528516, 6596633, 22376891, 50009688, 52662966, 8325398, 22665558,
        3689317,
    ];
    const N0: u64 = 33602639;
}

pub type ScalarP256 = Montgomery<10, ScalarP256Params>;

impl ScalarP256 {
    pub(super) fn to_bytes(self) -> [u8; 32] {
        let mut bytes = self.to_le_bytes();
        bytes.reverse();
        bytes
    }

    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut bytes = *bytes;
        bytes.reverse();
        let (chunks, _) = bytes.as_chunks::<4>();
        let mut w = [0u32; 8];
        for (i, chunk) in chunks.iter().enumerate() {
            w[i] = u32::from_le_bytes(*chunk);
        }
        let mut s = Self::ZERO;
        s[0] = w[0] & Self::MASK;
        s[1] = ((w[0] >> 26) | (w[1] << 6)) & Self::MASK;
        s[2] = ((w[1] >> 20) | (w[2] << 12)) & Self::MASK;
        s[3] = ((w[2] >> 14) | (w[3] << 18)) & Self::MASK;
        s[4] = ((w[3] >> 8) | (w[4] << 24)) & Self::MASK;
        s[5] = (w[4] >> 2) & Self::MASK;
        s[6] = ((w[4] >> 28) | (w[5] << 4)) & Self::MASK;
        s[7] = ((w[5] >> 22) | (w[6] << 10)) & Self::MASK;
        s[8] = ((w[6] >> 16) | (w[7] << 16)) & Self::MASK;
        s[9] = (w[7] >> 10) & Self::TOP_MASK;
        s.enter_montgomery()
    }

    pub(super) fn to_le_bytes(self) -> [u8; 32] {
        let s = self.exit_montgomery();
        let w = [
            s[0] | (s[1] << 26),
            (s[1] >> 6) | (s[2] << 20),
            (s[2] >> 12) | (s[3] << 14),
            (s[3] >> 18) | (s[4] << 8),
            (s[4] >> 24) | (s[5] << 2) | (s[6] << 28),
            (s[6] >> 4) | (s[7] << 22),
            (s[7] >> 10) | (s[8] << 16),
            (s[8] >> 16) | (s[9] << 10),
        ];
        let mut bytes = [0u8; 32];
        let (chunks, _) = bytes.as_chunks_mut::<4>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&w[i].to_le_bytes());
        }
        bytes
    }
}
