use crate::{elliptic_curves::Montgomery, traits::MontgomeryParams};

#[derive(Clone, Copy)]
pub struct FieldP384Params;

impl MontgomeryParams<7> for FieldP384Params {
    const BITS: u32 = 56;
    const TOP_BITS: u32 = 48;
    const MOD: [u64; 7] = [
        4294967295,
        72056494526300160,
        72057594037862399,
        72057594037927935,
        72057594037927935,
        72057594037927935,
        281474976710655,
    ];
    const R: [u64; 7] = [72056494526300416, 281474976710655, 16777216, 0, 0, 0, 0];
    const R2: [u64; 7] = [
        71494644084572160,
        16777215,
        2,
        1099511627264,
        281474976841728,
        0,
        0,
    ];
    const N0: u64 = 4294967297;
}

pub type FieldP384 = Montgomery<7, FieldP384Params>;

impl FieldP384 {
    pub(super) fn from_u32(value: u32) -> Self {
        let mut s = Self::ZERO;
        s[0] = value as u64;
        s.enter_montgomery()
    }

    pub(super) fn from_bytes(bytes: &[u8; 48]) -> Self {
        let mut bytes = *bytes;
        bytes.reverse();
        let mut s = Self::ZERO;
        for i in 0..6 {
            let mut b = [0u8; 8];
            b[..7].copy_from_slice(&bytes[7 * i..7 * i + 7]);
            s[i] = u64::from_le_bytes(b);
        }
        let mut b = [0u8; 8];
        b[..6].copy_from_slice(&bytes[42..48]);
        s[6] = u64::from_le_bytes(b);
        s.enter_montgomery()
    }

    pub(super) fn to_bytes(self) -> [u8; 48] {
        let s = self.exit_montgomery();
        let mut bytes = [0u8; 48];
        for i in 0..6 {
            bytes[7 * i..7 * i + 7].copy_from_slice(&s[i].to_le_bytes()[..7]);
        }
        bytes[42..48].copy_from_slice(&s[6].to_le_bytes()[..6]);
        bytes.reverse();
        bytes
    }
}
