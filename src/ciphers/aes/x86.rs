#![allow(unsafe_code)]
#[cfg(target_arch = "x86")]
use core::arch::x86::{
    __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_and_si128, _mm_clmulepi64_si128,
    _mm_cvtsi128_si32, _mm_set_epi64x, _mm_slli_si128, _mm_srli_si128, _mm_xor_si128,
};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_and_si128, _mm_clmulepi64_si128,
    _mm_cvtsi128_si32, _mm_set_epi64x, _mm_slli_si128, _mm_srli_si128, _mm_xor_si128,
};

pub(super) const fn is_accelerated() -> bool {
    true
}

pub(super) fn encrypt_blocks<const ROUNDS: usize, const N: usize>(
    round_keys: &[[u8; 16]; 15],
    blocks: &[[u8; 16]; N],
    data: &mut [[u8; 16]; N],
) {
    unsafe {
        let keys = round_keys.map(load);
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
}

pub(super) fn multiply<const N: usize>(x: &[u128; N], h: &[u128; N]) -> u128 {
    unsafe {
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
}

fn split(value: u128) -> __m128i {
    unsafe { _mm_set_epi64x((value >> 64) as i64, value as i64) }
}

fn join(value: __m128i) -> u128 {
    unsafe {
        let a = _mm_cvtsi128_si32(value) as u32;
        let b = _mm_cvtsi128_si32(_mm_srli_si128::<4>(value)) as u32;
        let c = _mm_cvtsi128_si32(_mm_srli_si128::<8>(value)) as u32;
        let d = _mm_cvtsi128_si32(_mm_srli_si128::<12>(value)) as u32;
        (d as u128) << 96 | (c as u128) << 64 | (b as u128) << 32 | a as u128
    }
}

fn load(block: [u8; 16]) -> __m128i {
    split(u128::from_le_bytes(block))
}

fn store(state: __m128i) -> [u8; 16] {
    join(state).to_le_bytes()
}

fn rounds<const N: usize>(a: [__m128i; N], b: [__m128i; N]) -> [__m128i; N] {
    let mut out = a;
    for (out, b) in out.iter_mut().zip(b) {
        *out = unsafe { _mm_aesenc_si128(*out, b) };
    }
    out
}

fn xor(a: __m128i, b: __m128i) -> __m128i {
    unsafe { _mm_xor_si128(a, b) }
}

fn and(a: __m128i, b: __m128i) -> __m128i {
    unsafe { _mm_and_si128(a, b) }
}

impl_aegis_backend!(__m128i, load, store, xor, and, rounds);
