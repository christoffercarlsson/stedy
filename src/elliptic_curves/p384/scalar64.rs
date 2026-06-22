use crate::{elliptic_curves::Montgomery, traits::MontgomeryParams};

#[derive(Clone, Copy)]
pub struct ScalarP384Params;

impl MontgomeryParams<7> for ScalarP384Params {
    const BITS: u32 = 56;
    const TOP_BITS: u32 = 48;
    const MOD: [u64; 7] = [
        66456040996415859,
        3855199968393964,
        36578789825665050,
        72057594034217805,
        72057594037927935,
        72057594037927935,
        281474976710655,
    ];
    const R: [u64; 7] = [
        64903291906460928,
        21875124622136083,
        3317029560378866,
        949793406,
        0,
        0,
        0,
    ];
    const R2: [u64; 7] = [
        15196389769100468,
        32586093657240672,
        19042089156402130,
        8098723524601070,
        42172925055814315,
        17926830470735464,
        261688787582753,
    ];
    const N0: u64 = 59778840491187269;
}

pub type ScalarP384 = Montgomery<7, ScalarP384Params>;

impl ScalarP384 {
    pub(super) fn from_bytes(bytes: &[u8; 48]) -> Self {
        let mut bytes = *bytes;
        bytes.reverse();
        let (chunks, _) = bytes.as_chunks::<8>();
        let mut words = [0u64; 6];
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u64::from_le_bytes(*chunk);
        }
        let mut s = Self::ZERO;
        s[0] = words[0] & Self::MASK;
        s[1] = ((words[0] >> 56) | (words[1] << 8)) & Self::MASK;
        s[2] = ((words[1] >> 48) | (words[2] << 16)) & Self::MASK;
        s[3] = ((words[2] >> 40) | (words[3] << 24)) & Self::MASK;
        s[4] = ((words[3] >> 32) | (words[4] << 32)) & Self::MASK;
        s[5] = ((words[4] >> 24) | (words[5] << 40)) & Self::MASK;
        s[6] = (words[5] >> 16) & Self::TOP_MASK;
        s.enter_montgomery()
    }

    pub(super) fn to_le_bytes(self) -> [u8; 48] {
        let s = self.exit_montgomery();
        let words = [
            s[0] | (s[1] << 56),
            (s[1] >> 8) | (s[2] << 48),
            (s[2] >> 16) | (s[3] << 40),
            (s[3] >> 24) | (s[4] << 32),
            (s[4] >> 32) | (s[5] << 24),
            (s[5] >> 40) | (s[6] << 16),
        ];
        let mut bytes = [0u8; 48];
        let (chunks, _) = bytes.as_chunks_mut::<8>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&words[i].to_le_bytes());
        }
        bytes
    }

    pub(super) fn to_bytes(self) -> [u8; 48] {
        let mut bytes = self.to_le_bytes();
        bytes.reverse();
        bytes
    }
}
