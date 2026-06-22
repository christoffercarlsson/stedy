use crate::{elliptic_curves::Montgomery, traits::MontgomeryParams};

#[derive(Clone, Copy)]
pub struct FieldP384Params;

impl MontgomeryParams<14> for FieldP384Params {
    const BITS: u32 = 28;
    const TOP_BITS: u32 = 20;
    const MOD: [u64; 14] = [
        268435455, 15, 0, 268431360, 268369919, 268435455, 268435455, 268435455, 268435455,
        268435455, 268435455, 268435455, 268435455, 1048575,
    ];
    const R: [u64; 14] = [
        256, 268431360, 268435455, 1048575, 16777216, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    const R2: [u64; 14] = [
        65536, 266338304, 16777215, 0, 2, 0, 268434944, 4095, 131072, 1048576, 0, 0, 0, 0,
    ];
    const N0: u64 = 1;
}

pub type FieldP384 = Montgomery<14, FieldP384Params>;

impl FieldP384 {
    pub(super) fn from_u32(value: u32) -> Self {
        let mut s = Self::ZERO;
        s[0] = value & Self::MASK;
        s[1] = value >> 28;
        s.enter_montgomery()
    }

    pub(super) fn from_bytes(bytes: &[u8; 48]) -> Self {
        let mut bytes = *bytes;
        bytes.reverse();
        let (chunks, _) = bytes.as_chunks::<4>();
        let mut w = [0u32; 12];
        for (i, chunk) in chunks.iter().enumerate() {
            w[i] = u32::from_le_bytes(*chunk);
        }
        let mut s = Self::ZERO;
        s[0] = w[0] & Self::MASK;
        s[1] = ((w[0] >> 28) | (w[1] << 4)) & Self::MASK;
        s[2] = ((w[1] >> 24) | (w[2] << 8)) & Self::MASK;
        s[3] = ((w[2] >> 20) | (w[3] << 12)) & Self::MASK;
        s[4] = ((w[3] >> 16) | (w[4] << 16)) & Self::MASK;
        s[5] = ((w[4] >> 12) | (w[5] << 20)) & Self::MASK;
        s[6] = ((w[5] >> 8) | (w[6] << 24)) & Self::MASK;
        s[7] = (w[6] >> 4) & Self::MASK;
        s[8] = w[7] & Self::MASK;
        s[9] = ((w[7] >> 28) | (w[8] << 4)) & Self::MASK;
        s[10] = ((w[8] >> 24) | (w[9] << 8)) & Self::MASK;
        s[11] = ((w[9] >> 20) | (w[10] << 12)) & Self::MASK;
        s[12] = ((w[10] >> 16) | (w[11] << 16)) & Self::MASK;
        s[13] = (w[11] >> 12) & Self::TOP_MASK;
        s.enter_montgomery()
    }

    pub(super) fn to_bytes(self) -> [u8; 48] {
        let s = self.exit_montgomery();
        let w = [
            s[0] | (s[1] << 28),
            (s[1] >> 4) | (s[2] << 24),
            (s[2] >> 8) | (s[3] << 20),
            (s[3] >> 12) | (s[4] << 16),
            (s[4] >> 16) | (s[5] << 12),
            (s[5] >> 20) | (s[6] << 8),
            (s[6] >> 24) | (s[7] << 4),
            s[8] | (s[9] << 28),
            (s[9] >> 4) | (s[10] << 24),
            (s[10] >> 8) | (s[11] << 20),
            (s[11] >> 12) | (s[12] << 16),
            (s[12] >> 16) | (s[13] << 12),
        ];
        let mut bytes = [0u8; 48];
        let (chunks, _) = bytes.as_chunks_mut::<4>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&w[i].to_le_bytes());
        }
        bytes.reverse();
        bytes
    }
}
