use crate::{elliptic_curves::Montgomery, traits::MontgomeryParams};

#[derive(Clone, Copy)]
pub struct FieldP256Params;

impl MontgomeryParams<10> for FieldP256Params {
    const BITS: u32 = 26;
    const TOP_BITS: u32 = 22;
    const MOD: [u64; 10] = [
        67108863, 67108863, 67108863, 262143, 0, 0, 0, 1024, 67043328, 4194303,
    ];
    const R: [u64; 10] = [
        16, 0, 0, 62914560, 67108863, 67108863, 67108863, 67092479, 1048575, 0,
    ];
    const R2: [u64; 10] = [
        768, 0, 66060288, 67108863, 67108859, 67108799, 67108863, 66584575, 16777215, 1,
    ];
    const N0: u64 = 1;
}

pub type FieldP256 = Montgomery<10, FieldP256Params>;

impl FieldP256 {
    pub(super) fn from_u32(value: u32) -> Self {
        let mut s = Self::ZERO;
        s[0] = value as u64;
        s.enter_montgomery()
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

    pub(super) fn to_bytes(self) -> [u8; 32] {
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
        bytes.reverse();
        bytes
    }
}
