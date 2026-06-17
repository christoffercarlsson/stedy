use crate::{elliptic_curves::Montgomery, traits::MontgomeryParams};

#[derive(Clone, Copy)]
pub struct Scalar25519Params;

impl MontgomeryParams<5> for Scalar25519Params {
    const BITS: u32 = 52;
    const TOP_BITS: u32 = 48;
    const MOD: [u64; 5] = [
        671914833335277,
        3916664325105025,
        1367801,
        0,
        17592186044416,
    ];
    const R: [u64; 5] = [
        4302102966953709,
        1049714374468698,
        4503599278581019,
        4503599627370495,
        17592186044415,
    ];
    const R2: [u64; 5] = [
        2764609938444603,
        3768881411696287,
        1616719297148420,
        1087343033131391,
        10175238647962,
    ];
    const N0: u64 = 1439961107955227;
}

pub type Scalar25519 = Montgomery<5, Scalar25519Params>;

impl Scalar25519 {
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Self {
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

    pub(crate) fn from_wide_bytes(bytes: &[u8; 64]) -> Self {
        let (chunks, _) = bytes.as_chunks::<8>();
        let mut words = [0u64; 8];
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u64::from_le_bytes(*chunk);
        }
        let mut lo = Self::ZERO;
        let mut hi = Self::ZERO;
        lo[0] = words[0] & Self::MASK;
        lo[1] = ((words[0] >> 52) | (words[1] << 12)) & Self::MASK;
        lo[2] = ((words[1] >> 40) | (words[2] << 24)) & Self::MASK;
        lo[3] = ((words[2] >> 28) | (words[3] << 36)) & Self::MASK;
        lo[4] = ((words[3] >> 16) | (words[4] << 48)) & Self::MASK;
        hi[0] = (words[4] >> 4) & Self::MASK;
        hi[1] = ((words[4] >> 56) | (words[5] << 8)) & Self::MASK;
        hi[2] = ((words[5] >> 44) | (words[6] << 20)) & Self::MASK;
        hi[3] = ((words[6] >> 32) | (words[7] << 32)) & Self::MASK;
        hi[4] = words[7] >> 20;
        lo *= Self::R;
        hi *= Self::R2;
        (hi + lo).enter_montgomery()
    }

    pub(crate) fn to_bytes(self) -> [u8; 32] {
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
        bytes
    }
}
