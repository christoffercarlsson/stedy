use crate::{elliptic_curves::Montgomery, traits::MontgomeryParams};

#[derive(Clone, Copy)]
pub struct ScalarP521Params;

impl MontgomeryParams<18> for ScalarP521Params {
    const BITS: u32 = 29;
    const TOP_BITS: u32 = 28;
    const MOD: [u64; 18] = [
        288908297, 461224180, 118614958, 194212115, 442303419, 10779524, 430833456, 276293106,
        441550471, 536870911, 536870911, 536870911, 536870911, 536870911, 536870911, 536870911,
        536870911, 268435455,
    ];
    const R: [u64; 18] = [
        495925230, 151293462, 299640994, 148446681, 189134985, 515311862, 212074911, 521155610,
        190640880, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    const R2: [u64; 18] = [
        337387844, 224901955, 67276000, 477686182, 141919886, 99016278, 241547183, 111883419,
        463822556, 333342713, 361145237, 145455501, 290008333, 158101534, 51449359, 380925437,
        421149093, 67695873,
    ];
    const N0: u64 = 430544327;
}

pub type ScalarP521 = Montgomery<18, ScalarP521Params>;

impl ScalarP521 {
    pub(super) fn from_bytes(bytes: &[u8; 66]) -> Self {
        let mut bytes = *bytes;
        bytes.reverse();
        let mut words = [0u32; 16];
        let (chunks, remainder) = bytes.as_chunks::<4>();
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u32::from_le_bytes(*chunk);
        }
        let top_word = (remainder[0] as u32) | ((remainder[1] as u32 & 1) << 8);
        let mut s = Self::ZERO;
        s[0] = words[0] & Self::MASK;
        s[1] = ((words[0] >> 29) | (words[1] << 3)) & Self::MASK;
        s[2] = ((words[1] >> 26) | (words[2] << 6)) & Self::MASK;
        s[3] = ((words[2] >> 23) | (words[3] << 9)) & Self::MASK;
        s[4] = ((words[3] >> 20) | (words[4] << 12)) & Self::MASK;
        s[5] = ((words[4] >> 17) | (words[5] << 15)) & Self::MASK;
        s[6] = ((words[5] >> 14) | (words[6] << 18)) & Self::MASK;
        s[7] = ((words[6] >> 11) | (words[7] << 21)) & Self::MASK;
        s[8] = ((words[7] >> 8) | (words[8] << 24)) & Self::MASK;
        s[9] = ((words[8] >> 5) | (words[9] << 27)) & Self::MASK;
        s[10] = (words[9] >> 2) & Self::MASK;
        s[11] = ((words[9] >> 31) | (words[10] << 1)) & Self::MASK;
        s[12] = ((words[10] >> 28) | (words[11] << 4)) & Self::MASK;
        s[13] = ((words[11] >> 25) | (words[12] << 7)) & Self::MASK;
        s[14] = ((words[12] >> 22) | (words[13] << 10)) & Self::MASK;
        s[15] = ((words[13] >> 19) | (words[14] << 13)) & Self::MASK;
        s[16] = ((words[14] >> 16) | (words[15] << 16)) & Self::MASK;
        s[17] = ((words[15] >> 13) | (top_word << 19)) & Self::TOP_MASK;
        s.enter_montgomery()
    }

    pub(super) fn to_bytes(self) -> [u8; 66] {
        let mut bytes = self.to_le_bytes();
        bytes.reverse();
        bytes
    }

    pub(super) fn to_le_bytes(self) -> [u8; 66] {
        let s = self.exit_montgomery();
        let words = [
            s[0] | (s[1] << 29),
            (s[1] >> 3) | (s[2] << 26),
            (s[2] >> 6) | (s[3] << 23),
            (s[3] >> 9) | (s[4] << 20),
            (s[4] >> 12) | (s[5] << 17),
            (s[5] >> 15) | (s[6] << 14),
            (s[6] >> 18) | (s[7] << 11),
            (s[7] >> 21) | (s[8] << 8),
            (s[8] >> 24) | (s[9] << 5),
            (s[9] >> 27) | (s[10] << 2) | (s[11] << 31),
            (s[11] >> 1) | (s[12] << 28),
            (s[12] >> 4) | (s[13] << 25),
            (s[13] >> 7) | (s[14] << 22),
            (s[14] >> 10) | (s[15] << 19),
            (s[15] >> 13) | (s[16] << 16),
            (s[16] >> 16) | (s[17] << 13),
        ];
        let mut bytes = [0u8; 66];
        let (chunks, remainder) = bytes.as_chunks_mut::<4>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&words[i].to_le_bytes());
        }
        remainder[0] = (s[17] >> 19) as u8;
        remainder[1] = (s[17] >> 27) as u8 & 1;
        bytes
    }
}
