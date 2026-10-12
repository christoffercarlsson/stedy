use {
    crate::utils::Secret,
    core::ops::{BitAnd, BitXor},
};

pub(super) const fn is_accelerated() -> bool {
    false
}

pub(super) fn encrypt_blocks<const ROUNDS: usize, const N: usize>(
    round_keys: &[[u8; 16]; 15],
    blocks: &[[u8; 16]; N],
    data: &mut [[u8; 16]; N],
) {
    let keys = Secret::from(round_keys.map(|key| key_planes(u128::from_le_bytes(key))));
    let mut planes = Secret::from([0u128; 8]);
    for (plane, block) in planes.get_mut()[..N].iter_mut().zip(blocks) {
        *plane = u128::from_le_bytes(*block);
    }
    transpose(planes.get_mut());
    add_round_key(planes.get_mut(), &keys[0]);
    for key in &keys.get()[1..ROUNDS] {
        sub_bytes(planes.get_mut());
        shift_rows(planes.get_mut());
        mix_columns(planes.get_mut());
        add_round_key(planes.get_mut(), key);
    }
    sub_bytes(planes.get_mut());
    shift_rows(planes.get_mut());
    add_round_key(planes.get_mut(), &keys[ROUNDS]);
    transpose(planes.get_mut());
    for (block, state) in data.iter_mut().zip(planes.get()) {
        *block = (u128::from_le_bytes(*block) ^ state).to_le_bytes();
    }
}

pub(super) fn multiply<const N: usize>(x: &[u128; N], h: &[u128; N]) -> u128 {
    let (mut lo, mut mid, mut hi) = (0u128, 0u128, 0u128);
    for (a, b) in x.iter().zip(h) {
        let (a0, a1) = split(*a);
        let (b0, b1) = split(*b);
        lo ^= clmul(a0, b0);
        hi ^= clmul(a1, b1);
        mid ^= clmul(a0 ^ a1, b0 ^ b1);
    }
    let mid = mid ^ lo ^ hi;
    let lo = lo ^ (mid << 64);
    let hi = hi ^ (mid >> 64);
    let (hi0, hi1) = split(hi);
    let fold = reduce(hi1);
    let lo = lo ^ (fold << 64);
    lo ^ reduce(hi0 ^ (fold >> 64) as u64)
}

fn split(value: u128) -> (u64, u64) {
    (value as u64, (value >> 64) as u64)
}

fn reduce(value: u64) -> u128 {
    let value = value as u128;
    value ^ (value << 1) ^ (value << 2) ^ (value << 7)
}

fn clmul(a: u64, b: u64) -> u128 {
    let low = masked_mul(a, b);
    let high = masked_mul(a.reverse_bits(), b.reverse_bits()).reverse_bits() >> 1;
    (high as u128) << 64 | low as u128
}

fn masked_mul(a: u64, b: u64) -> u64 {
    const MASKS: [u64; 4] = [
        0x1111_1111_1111_1111,
        0x2222_2222_2222_2222,
        0x4444_4444_4444_4444,
        0x8888_8888_8888_8888,
    ];
    let a = MASKS.map(|mask| a & mask);
    let b = MASKS.map(|mask| b & mask);
    let mut products = [0u64; 4];
    for (i, a) in a.iter().enumerate() {
        for (j, b) in b.iter().enumerate() {
            products[(i + j) % 4] ^= a.wrapping_mul(*b);
        }
    }
    let mut product = 0;
    for (p, mask) in products.iter().zip(MASKS) {
        product |= p & mask;
    }
    product
}

fn key_planes(key: u128) -> [u128; 8] {
    core::array::from_fn(|bit| ((key >> bit) & splat(0x0101_0101)).wrapping_mul(0xff))
}

fn transpose(planes: &mut [u128; 8]) {
    for i in [0, 2, 4, 6] {
        swap_bits(planes, i, i + 1, splat(0x5555_5555), 1);
    }
    for i in [0, 1, 4, 5] {
        swap_bits(planes, i, i + 2, splat(0x3333_3333), 2);
    }
    for i in [0, 1, 2, 3] {
        swap_bits(planes, i, i + 4, splat(0x0f0f_0f0f), 4);
    }
}

fn swap_bits(planes: &mut [u128; 8], a: usize, b: usize, mask: u128, shift: u32) {
    let swap = ((planes[a] >> shift) ^ planes[b]) & mask;
    planes[b] ^= swap;
    planes[a] ^= swap << shift;
}

fn add_round_key(planes: &mut [u128; 8], key: &[u128; 8]) {
    for (plane, key) in planes.iter_mut().zip(key) {
        *plane ^= key;
    }
}

fn sub_bytes(planes: &mut [u128; 8]) {
    let [u7, u6, u5, u4, u3, u2, u1, u0] = *planes;
    let t1 = u0 ^ u3;
    let t2 = u0 ^ u5;
    let t3 = u0 ^ u6;
    let t4 = u3 ^ u5;
    let t5 = u4 ^ u6;
    let t6 = t1 ^ t5;
    let t7 = u1 ^ u2;
    let t8 = u7 ^ t6;
    let t9 = u7 ^ t7;
    let t10 = t6 ^ t7;
    let t11 = u1 ^ u5;
    let t12 = u2 ^ u5;
    let t13 = t3 ^ t4;
    let t14 = t6 ^ t11;
    let t15 = t5 ^ t11;
    let t16 = t5 ^ t12;
    let t17 = t9 ^ t16;
    let t18 = u3 ^ u7;
    let t19 = t7 ^ t18;
    let t20 = t1 ^ t19;
    let t21 = u6 ^ u7;
    let t22 = t7 ^ t21;
    let t23 = t2 ^ t22;
    let t24 = t2 ^ t10;
    let t25 = t20 ^ t17;
    let t26 = t3 ^ t16;
    let t27 = t1 ^ t12;
    let m1 = t13 & t6;
    let m2 = t23 & t8;
    let m3 = t14 ^ m1;
    let m4 = t19 & u7;
    let m5 = m4 ^ m1;
    let m6 = t3 & t16;
    let m7 = t22 & t9;
    let m8 = t26 ^ m6;
    let m9 = t20 & t17;
    let m10 = m9 ^ m6;
    let m11 = t1 & t15;
    let m12 = t4 & t27;
    let m13 = m12 ^ m11;
    let m14 = t2 & t10;
    let m15 = m14 ^ m11;
    let m16 = m3 ^ m2;
    let m17 = m5 ^ t24;
    let m18 = m8 ^ m7;
    let m19 = m10 ^ m15;
    let m20 = m16 ^ m13;
    let m21 = m17 ^ m15;
    let m22 = m18 ^ m13;
    let m23 = m19 ^ t25;
    let m24 = m22 ^ m23;
    let m25 = m22 & m20;
    let m26 = m21 ^ m25;
    let m27 = m20 ^ m21;
    let m28 = m23 ^ m25;
    let m29 = m28 & m27;
    let m30 = m26 & m24;
    let m31 = m20 & m23;
    let m32 = m27 & m31;
    let m33 = m27 ^ m25;
    let m34 = m21 & m22;
    let m35 = m24 & m34;
    let m36 = m24 ^ m25;
    let m37 = m21 ^ m29;
    let m38 = m32 ^ m33;
    let m39 = m23 ^ m30;
    let m40 = m35 ^ m36;
    let m41 = m38 ^ m40;
    let m42 = m37 ^ m39;
    let m43 = m37 ^ m38;
    let m44 = m39 ^ m40;
    let m45 = m42 ^ m41;
    let m46 = m44 & t6;
    let m47 = m40 & t8;
    let m48 = m39 & u7;
    let m49 = m43 & t16;
    let m50 = m38 & t9;
    let m51 = m37 & t17;
    let m52 = m42 & t15;
    let m53 = m45 & t27;
    let m54 = m41 & t10;
    let m55 = m44 & t13;
    let m56 = m40 & t23;
    let m57 = m39 & t19;
    let m58 = m43 & t3;
    let m59 = m38 & t22;
    let m60 = m37 & t20;
    let m61 = m42 & t1;
    let m62 = m45 & t4;
    let m63 = m41 & t2;
    let l0 = m61 ^ m62;
    let l1 = m50 ^ m56;
    let l2 = m46 ^ m48;
    let l3 = m47 ^ m55;
    let l4 = m54 ^ m58;
    let l5 = m49 ^ m61;
    let l6 = m62 ^ l5;
    let l7 = m46 ^ l3;
    let l8 = m51 ^ m59;
    let l9 = m52 ^ m53;
    let l10 = m53 ^ l4;
    let l11 = m60 ^ l2;
    let l12 = m48 ^ m51;
    let l13 = m50 ^ l0;
    let l14 = m52 ^ m61;
    let l15 = m55 ^ l1;
    let l16 = m56 ^ l0;
    let l17 = m57 ^ l1;
    let l18 = m58 ^ l8;
    let l19 = m63 ^ l4;
    let l20 = l0 ^ l1;
    let l21 = l1 ^ l7;
    let l22 = l3 ^ l12;
    let l23 = l18 ^ l2;
    let l24 = l15 ^ l9;
    let l25 = l6 ^ l10;
    let l26 = l7 ^ l9;
    let l27 = l8 ^ l10;
    let l28 = l11 ^ l14;
    let l29 = l11 ^ l17;
    let s0 = l6 ^ l24;
    let s1 = !(l16 ^ l26);
    let s2 = !(l19 ^ l28);
    let s3 = l6 ^ l21;
    let s4 = l20 ^ l22;
    let s5 = l25 ^ l29;
    let s6 = !(l13 ^ l27);
    let s7 = !(l6 ^ l23);
    *planes = [s7, s6, s5, s4, s3, s2, s1, s0];
}

fn shift_rows(planes: &mut [u128; 8]) {
    for plane in planes.iter_mut() {
        *plane = (*plane & splat(0x0000_00ff))
            | (*plane & splat(0x0000_ff00)).rotate_right(32)
            | (*plane & splat(0x00ff_0000)).rotate_right(64)
            | (*plane & splat(0xff00_0000)).rotate_right(96);
    }
}

fn mix_columns(planes: &mut [u128; 8]) {
    let mut t = [0u128; 8];
    let mut u = [0u128; 8];
    for ((t, u), plane) in t.iter_mut().zip(u.iter_mut()).zip(planes.iter()) {
        let next = rotate_column::<8>(*plane);
        *t = plane ^ next;
        *u = next ^ rotate_column::<16>(*t);
    }
    planes[0] = u[0] ^ t[7];
    planes[1] = u[1] ^ t[0] ^ t[7];
    planes[2] = u[2] ^ t[1];
    planes[3] = u[3] ^ t[2] ^ t[7];
    planes[4] = u[4] ^ t[3] ^ t[7];
    planes[5] = u[5] ^ t[4];
    planes[6] = u[6] ^ t[5];
    planes[7] = u[7] ^ t[6];
}

fn rotate_column<const BITS: u32>(plane: u128) -> u128 {
    let low = splat(u32::MAX >> BITS);
    ((plane >> BITS) & low) | ((plane << (32 - BITS)) & !low)
}

const fn splat(word: u32) -> u128 {
    let word = word as u128;
    word | word << 32 | word << 64 | word << 96
}

fn rounds<const N: usize>(a: [u128; N], b: [u128; N]) -> [u128; N] {
    let mut planes = Secret::from([0u128; 8]);
    planes.get_mut()[..N].copy_from_slice(&a);
    transpose(planes.get_mut());
    sub_bytes(planes.get_mut());
    shift_rows(planes.get_mut());
    mix_columns(planes.get_mut());
    transpose(planes.get_mut());
    let mut out = b;
    for (out, plane) in out.iter_mut().zip(planes.get()) {
        *out ^= plane;
    }
    out
}

impl_aegis_backend!(
    u128,
    u128::from_le_bytes,
    u128::to_le_bytes,
    BitXor::bitxor,
    BitAnd::bitand,
    rounds
);
