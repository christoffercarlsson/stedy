use crate::{elliptic_curves::Montgomery, traits::MontgomeryParams};

#[derive(Clone, Copy)]
pub struct ScalarP521Params;

impl MontgomeryParams<9> for ScalarP521Params {
    const BITS: u32 = 58;
    const TOP_BITS: u32 = 57;
    const MOD: [u64; 9] = [
        247617846441960457,
        104266835420113838,
        5787213323109307,
        148333732228366128,
        288230376056391303,
        288230376151711743,
        288230376151711743,
        288230376151711743,
        144115188075855871,
    ];
    const R: [u64; 9] = [
        81225059419502574,
        79696705311484066,
        276655949505493129,
        279793287846691231,
        190640880,
        0,
        0,
        0,
        0,
    ];
    const R2: [u64; 9] = [
        120743318028820804,
        256455816247413984,
        53158959614625422,
        60066953437755311,
        178962006800686812,
        78090827838432149,
        84880115037187341,
        204507786817637903,
        36343945497295269,
    ];
    const N0: u64 = 85388955522536903;
}

pub type ScalarP521 = Montgomery<9, ScalarP521Params>;

impl ScalarP521 {
    pub(super) fn from_bytes(bytes: &[u8; 66]) -> Self {
        let mut bytes = *bytes;
        bytes.reverse();
        let mut words = [0u64; 8];
        let (chunks, remainder) = bytes.as_chunks::<8>();
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u64::from_le_bytes(*chunk);
        }
        let top_word = (remainder[0] as u64) | ((remainder[1] as u64 & 1) << 8);
        let mut s = Self::ZERO;
        s[0] = words[0] & Self::MASK;
        s[1] = ((words[0] >> 58) | (words[1] << 6)) & Self::MASK;
        s[2] = ((words[1] >> 52) | (words[2] << 12)) & Self::MASK;
        s[3] = ((words[2] >> 46) | (words[3] << 18)) & Self::MASK;
        s[4] = ((words[3] >> 40) | (words[4] << 24)) & Self::MASK;
        s[5] = ((words[4] >> 34) | (words[5] << 30)) & Self::MASK;
        s[6] = ((words[5] >> 28) | (words[6] << 36)) & Self::MASK;
        s[7] = ((words[6] >> 22) | (words[7] << 42)) & Self::MASK;
        s[8] = ((words[7] >> 16) | (top_word << 48)) & Self::TOP_MASK;
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
            s[0] | (s[1] << 58),
            (s[1] >> 6) | (s[2] << 52),
            (s[2] >> 12) | (s[3] << 46),
            (s[3] >> 18) | (s[4] << 40),
            (s[4] >> 24) | (s[5] << 34),
            (s[5] >> 30) | (s[6] << 28),
            (s[6] >> 36) | (s[7] << 22),
            (s[7] >> 42) | (s[8] << 16),
        ];
        let mut bytes = [0u8; 66];
        let (chunks, remainder) = bytes.as_chunks_mut::<8>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&words[i].to_le_bytes());
        }
        remainder[0] = (s[8] >> 48) as u8;
        remainder[1] = (s[8] >> 56) as u8 & 1;
        bytes
    }
}
