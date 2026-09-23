#![forbid(unsafe_code)]
use {
    core::arch::aarch64::{
        uint64x2_t, uint8x16_t, vaeseq_u8, vaesmcq_u8, vdupq_n_u64, veorq_u64, veorq_u8, vextq_u64,
        vgetq_lane_u64, vmull_high_p64, vmull_p64, vreinterpretq_p128_u64, vreinterpretq_p128_u8,
        vreinterpretq_p64_u64, vreinterpretq_u64_p128, vreinterpretq_u8_p128,
    },
    std::arch::is_aarch64_feature_detected,
};

pub(super) fn is_supported() -> bool {
    is_aarch64_feature_detected!("aes") && is_aarch64_feature_detected!("pmull")
}

#[target_feature(enable = "aes")]
pub(super) fn encrypt_blocks<const ROUNDS: usize, const N: usize>(
    round_keys: &[[u8; 16]; 15],
    blocks: &[[u8; 16]; N],
    data: &mut [[u8; 16]; N],
) {
    let keys = round_keys.map(|key| load(key));
    let mut states = blocks.map(|block| load(block));
    for key in &keys[..ROUNDS - 1] {
        for state in states.iter_mut() {
            *state = vaesmcq_u8(vaeseq_u8(*state, *key));
        }
    }
    for (state, block) in states.iter().zip(data.iter_mut()) {
        let state = veorq_u8(vaeseq_u8(*state, keys[ROUNDS - 1]), keys[ROUNDS]);
        *block = store(veorq_u8(state, load(*block)));
    }
}

#[target_feature(enable = "aes")]
pub(super) fn multiply<const N: usize>(x: &[u128; N], h: &[u128; N]) -> u128 {
    let zero = vdupq_n_u64(0);
    let (mut lo, mut mid, mut hi) = (zero, zero, zero);
    for (a, b) in x.iter().zip(h.iter()) {
        let a = split(*a);
        let b = split(*b);
        let swapped = vextq_u64::<1>(b, b);
        lo = veorq_u64(lo, clmul_low(a, b));
        hi = veorq_u64(hi, clmul_high(a, b));
        mid = veorq_u64(mid, clmul_low(a, swapped));
        mid = veorq_u64(mid, clmul_high(a, swapped));
    }
    let lo = veorq_u64(lo, vextq_u64::<1>(zero, mid));
    let hi = veorq_u64(hi, vextq_u64::<1>(mid, zero));
    let poly = vdupq_n_u64(0x87);
    let fold = clmul_high(hi, poly);
    let lo = veorq_u64(lo, vextq_u64::<1>(zero, fold));
    let hi = veorq_u64(hi, vextq_u64::<1>(fold, zero));
    join(veorq_u64(lo, clmul_low(hi, poly)))
}

#[target_feature(enable = "aes")]
fn clmul_low(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
    vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64::<0>(a), vgetq_lane_u64::<0>(b)))
}

#[target_feature(enable = "aes")]
fn clmul_high(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
    vreinterpretq_u64_p128(vmull_high_p64(
        vreinterpretq_p64_u64(a),
        vreinterpretq_p64_u64(b),
    ))
}

#[target_feature(enable = "aes")]
fn split(value: u128) -> uint64x2_t {
    vreinterpretq_u64_p128(value)
}

#[target_feature(enable = "aes")]
fn join(value: uint64x2_t) -> u128 {
    vreinterpretq_p128_u64(value)
}

#[target_feature(enable = "aes")]
fn load(block: [u8; 16]) -> uint8x16_t {
    vreinterpretq_u8_p128(u128::from_le_bytes(block))
}

#[target_feature(enable = "aes")]
fn store(state: uint8x16_t) -> [u8; 16] {
    vreinterpretq_p128_u8(state).to_le_bytes()
}
