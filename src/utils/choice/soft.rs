use {
    super::{Backend, Choice},
    core::hint::black_box,
};

pub fn opaque(value: u32) -> u32 {
    black_box(value)
}

pub fn opaque_choices(choices: &mut [Choice]) {
    black_box(choices);
}

impl Backend for u32 {
    fn assign(dst: &mut Self, src: Self, condition: u8) {
        let mask = black_box(u32::from(condition)).wrapping_neg();
        *dst ^= mask & (*dst ^ src);
    }
}

impl Backend for u64 {
    fn assign(dst: &mut Self, src: Self, condition: u8) {
        let mask = black_box(u64::from(condition)).wrapping_neg();
        *dst ^= mask & (*dst ^ src);
    }
}
