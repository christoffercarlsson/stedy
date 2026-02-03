use crate::{elliptic_curves::Montgomery, traits::MontgomeryParams};

#[derive(Clone, Copy)]
pub struct Scalar25519Params;

impl MontgomeryParams<10> for Scalar25519Params {
    const BITS: u32 = 26;
    const TOP_BITS: u32 = 22;
    const MOD: [u64; 10] = [
        16110573, 10012311, 30238081, 58362846, 1367801, 0, 0, 0, 0, 262144,
    ];
    const R: [u64; 10] = [
        52553453, 64106329, 6808666, 15641963, 53863707, 67108858, 67108863, 67108863, 67108863,
        262143,
    ];
    const R2: [u64; 10] = [
        22204731, 41195898, 29271711, 56160709, 57177604, 24090994, 54337919, 16202673, 58470554,
        151622,
    ];
    const N0: u64 = 39091739;
}

pub type Scalar25519 = Montgomery<10, Scalar25519Params>;

impl Scalar25519 {
    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Self {
        let (chunks, _) = bytes.as_chunks::<4>();
        let mut words = [0u32; 8];
        for (i, chunk) in chunks.iter().enumerate().take(8) {
            words[i] = u32::from_le_bytes(*chunk);
        }
        let mut s = Self::ZERO;
        s[0] = words[0] & Self::MASK;
        s[1] = ((words[0] >> 26) | (words[1] << 6)) & Self::MASK;
        s[2] = ((words[1] >> 20) | (words[2] << 12)) & Self::MASK;
        s[3] = ((words[2] >> 14) | (words[3] << 18)) & Self::MASK;
        s[4] = ((words[3] >> 8) | (words[4] << 24)) & Self::MASK;
        s[5] = (words[4] >> 2) & Self::MASK;
        s[6] = ((words[4] >> 28) | (words[5] << 4)) & Self::MASK;
        s[7] = ((words[5] >> 22) | (words[6] << 10)) & Self::MASK;
        s[8] = ((words[6] >> 16) | (words[7] << 16)) & Self::MASK;
        s[9] = (words[7] >> 10) & Self::TOP_MASK;
        s
    }

    pub(super) fn from_wide_bytes(bytes: &[u8; 64]) -> Self {
        let (chunks, _) = bytes.as_chunks::<4>();
        let mut words = [0u32; 16];
        for (i, chunk) in chunks.iter().enumerate().take(16) {
            words[i] = u32::from_le_bytes(*chunk);
        }
        let mut lo = Self::ZERO;
        let mut hi = Self::ZERO;
        lo[0] = words[0] & Self::MASK;
        lo[1] = ((words[0] >> 26) | (words[1] << 6)) & Self::MASK;
        lo[2] = ((words[1] >> 20) | (words[2] << 12)) & Self::MASK;
        lo[3] = ((words[2] >> 14) | (words[3] << 18)) & Self::MASK;
        lo[4] = ((words[3] >> 8) | (words[4] << 24)) & Self::MASK;
        lo[5] = (words[4] >> 2) & Self::MASK;
        lo[6] = ((words[4] >> 28) | (words[5] << 4)) & Self::MASK;
        lo[7] = ((words[5] >> 22) | (words[6] << 10)) & Self::MASK;
        lo[8] = ((words[6] >> 16) | (words[7] << 16)) & Self::MASK;
        lo[9] = ((words[7] >> 10) | (words[8] << 22)) & Self::MASK;
        hi[0] = (words[8] >> 4) & Self::MASK;
        hi[1] = ((words[8] >> 30) | (words[9] << 2)) & Self::MASK;
        hi[2] = ((words[9] >> 24) | (words[10] << 8)) & Self::MASK;
        hi[3] = ((words[10] >> 18) | (words[11] << 14)) & Self::MASK;
        hi[4] = ((words[11] >> 12) | (words[12] << 20)) & Self::MASK;
        hi[5] = (words[12] >> 6) & Self::MASK;
        hi[6] = words[13] & Self::MASK;
        hi[7] = ((words[13] >> 26) | (words[14] << 6)) & Self::MASK;
        hi[8] = ((words[14] >> 20) | (words[15] << 12)) & Self::MASK;
        hi[9] = words[15] >> 14;
        lo = lo.montgomery_mul(Self::R);
        hi = hi.montgomery_mul(Self::R2);
        hi.add(lo)
    }

    pub(super) fn to_bytes(self) -> [u8; 32] {
        let words = [
            self[0] | (self[1] << 26),
            (self[1] >> 6) | (self[2] << 20),
            (self[2] >> 12) | (self[3] << 14),
            (self[3] >> 18) | (self[4] << 8),
            (self[4] >> 24) | (self[5] << 2) | (self[6] << 28),
            (self[6] >> 4) | (self[7] << 22),
            (self[7] >> 10) | (self[8] << 16),
            (self[8] >> 16) | (self[9] << 10),
        ];
        let mut bytes = [0u8; 32];
        let (chunks, _) = bytes.as_chunks_mut::<4>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&words[i].to_le_bytes());
        }
        bytes
    }
}
