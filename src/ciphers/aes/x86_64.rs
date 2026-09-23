#![forbid(unsafe_code)]
use {
    core::arch::x86_64::{
        __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_clmulepi64_si128, _mm_cvtsi128_si64,
        _mm_set_epi64x, _mm_slli_si128, _mm_srli_si128, _mm_unpackhi_epi64, _mm_xor_si128,
    },
    std::arch::is_x86_feature_detected,
};

pub(super) fn is_supported() -> bool {
    is_x86_feature_detected!("aes") && is_x86_feature_detected!("pclmulqdq")
}

#[target_feature(enable = "aes")]
pub(super) fn encrypt_blocks<const ROUNDS: usize, const N: usize>(
    round_keys: &[[u8; 16]; 15],
    blocks: &[[u8; 16]; N],
    data: &mut [[u8; 16]; N],
) {
    let keys = round_keys.map(|key| load(key));
    let mut states = blocks.map(|block| _mm_xor_si128(load(block), keys[0]));
    for key in &keys[1..ROUNDS] {
        for state in states.iter_mut() {
            *state = _mm_aesenc_si128(*state, *key);
        }
    }
    for (state, block) in states.iter().zip(data.iter_mut()) {
        let state = _mm_aesenclast_si128(*state, keys[ROUNDS]);
        *block = store(_mm_xor_si128(state, load(*block)));
    }
}

#[target_feature(enable = "pclmulqdq")]
pub(super) fn multiply<const N: usize>(x: &[u128; N], h: &[u128; N]) -> u128 {
    let zero = _mm_set_epi64x(0, 0);
    let (mut lo, mut mid, mut hi) = (zero, zero, zero);
    for (a, b) in x.iter().zip(h.iter()) {
        let a = split(*a);
        let b = split(*b);
        lo = _mm_xor_si128(lo, _mm_clmulepi64_si128::<0x00>(a, b));
        hi = _mm_xor_si128(hi, _mm_clmulepi64_si128::<0x11>(a, b));
        mid = _mm_xor_si128(mid, _mm_clmulepi64_si128::<0x10>(a, b));
        mid = _mm_xor_si128(mid, _mm_clmulepi64_si128::<0x01>(a, b));
    }
    let lo = _mm_xor_si128(lo, _mm_slli_si128::<8>(mid));
    let hi = _mm_xor_si128(hi, _mm_srli_si128::<8>(mid));
    let poly = _mm_set_epi64x(0x87, 0x87);
    let fold = _mm_clmulepi64_si128::<0x01>(hi, poly);
    let lo = _mm_xor_si128(lo, _mm_slli_si128::<8>(fold));
    let hi = _mm_xor_si128(hi, _mm_srli_si128::<8>(fold));
    join(_mm_xor_si128(lo, _mm_clmulepi64_si128::<0x00>(hi, poly)))
}

#[target_feature(enable = "sse2")]
fn split(value: u128) -> __m128i {
    _mm_set_epi64x((value >> 64) as i64, value as i64)
}

#[target_feature(enable = "sse2")]
fn join(value: __m128i) -> u128 {
    let lo = _mm_cvtsi128_si64(value) as u64;
    let hi = _mm_cvtsi128_si64(_mm_unpackhi_epi64(value, value)) as u64;
    (hi as u128) << 64 | lo as u128
}

#[target_feature(enable = "sse2")]
fn load(block: [u8; 16]) -> __m128i {
    split(u128::from_le_bytes(block))
}

#[target_feature(enable = "sse2")]
fn store(state: __m128i) -> [u8; 16] {
    join(state).to_le_bytes()
}
