use crate::{elliptic_curves::Montgomery, traits::MontgomeryParams};

#[derive(Clone, Copy)]
pub struct FieldP256Params;

impl MontgomeryParams<5> for FieldP256Params {
    const BITS: u32 = 52;
    const TOP_BITS: u32 = 48;
    const MOD: [u64; 5] = [
        4503599627370495,
        17592186044415,
        0,
        68719476736,
        281474976645120,
    ];
    const R: [u64; 5] = [
        16,
        4222124650659840,
        4503599627370495,
        4502500115742719,
        1048575,
    ];
    const R2: [u64; 5] = [
        768,
        4503599626321920,
        4503595332403195,
        4468415255281663,
        83886079,
    ];
    const N0: u64 = 1;
}

pub type FieldP256 = Montgomery<5, FieldP256Params>;

impl FieldP256 {
    pub(super) fn from_u32(value: u32) -> Self {
        let mut s = Self::ZERO;
        s[0] = value as u64;
        s.enter_montgomery()
    }

    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut bytes = *bytes;
        bytes.reverse();
        let (chunks, _) = bytes.as_chunks::<8>();
        let mut words = [0u64; 4];
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u64::from_le_bytes(*chunk);
        }
        let mut s = Self::ZERO;
        s[0] = words[0] & Self::MASK;
        s[1] = ((words[0] >> 52) | (words[1] << 12)) & Self::MASK;
        s[2] = ((words[1] >> 40) | (words[2] << 24)) & Self::MASK;
        s[3] = ((words[2] >> 28) | (words[3] << 36)) & Self::MASK;
        s[4] = (words[3] >> 16) & Self::TOP_MASK;
        s.enter_montgomery()
    }

    pub(super) fn to_bytes(self) -> [u8; 32] {
        let s = self.exit_montgomery();
        let words = [
            s[0] | (s[1] << 52),
            (s[1] >> 12) | (s[2] << 40),
            (s[2] >> 24) | (s[3] << 28),
            (s[3] >> 36) | (s[4] << 16),
        ];
        let mut bytes = [0u8; 32];
        let (chunks, _) = bytes.as_chunks_mut::<8>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&words[i].to_le_bytes());
        }
        bytes.reverse();
        bytes
    }
}
