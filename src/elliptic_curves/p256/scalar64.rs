use crate::{elliptic_curves::Montgomery, traits::MontgomeryParams};

#[derive(Clone, Copy)]
pub struct ScalarP256Params;

impl MontgomeryParams<5> for ScalarP256Params {
    const BITS: u32 = 52;
    const TOP_BITS: u32 = 48;
    const MOD: [u64; 5] = [
        2756213597218129,
        3054930678533947,
        4503599622973178,
        68719476735,
        281474976645120,
    ];
    const R: [u64; 5] = [936578718214896, 660705044532294, 70357077, 4502500115742720, 1048575];
    const R2: [u64; 5] = [
        1631735023256506,
        442692611383428,
        3356093373051323,
        558708054790838,
        247585895471446,
    ];
    const N0: u64 = 502111439731791;
}

pub type ScalarP256 = Montgomery<5, ScalarP256Params>;

impl ScalarP256 {
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

    pub(super) fn to_le_bytes(self) -> [u8; 32] {
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

    pub(super) fn to_bytes(self) -> [u8; 32] {
        let mut bytes = self.to_le_bytes();
        bytes.reverse();
        bytes
    }
}
