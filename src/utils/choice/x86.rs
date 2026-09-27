use {super::Backend, core::arch::asm};

pub(super) fn opaque(mut value: u32) -> u32 {
    unsafe {
        asm!("/* {0:e} */", inout(reg) value, options(pure, nomem, nostack, preserves_flags));
    }
    value
}

impl Backend for u32 {
    fn assign(dst: &mut Self, src: Self, condition: u8) {
        unsafe {
            asm!(
                "test {condition}, {condition}",
                "cmovnz {dst:e}, {src:e}",
                condition = in(reg_byte) condition,
                dst = inout(reg) *dst,
                src = in(reg) src,
                options(pure, nomem, nostack),
            );
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl Backend for u64 {
    fn assign(dst: &mut Self, src: Self, condition: u8) {
        unsafe {
            asm!(
                "test {condition}, {condition}",
                "cmovnz {dst:r}, {src:r}",
                condition = in(reg_byte) condition,
                dst = inout(reg) *dst,
                src = in(reg) src,
                options(pure, nomem, nostack),
            );
        }
    }
}

#[cfg(target_arch = "x86")]
impl Backend for u64 {
    fn assign(dst: &mut Self, src: Self, condition: u8) {
        let mut low = *dst as u32;
        let mut high = (*dst >> 32) as u32;
        Backend::assign(&mut low, src as u32, condition);
        Backend::assign(&mut high, (src >> 32) as u32, condition);
        *dst = u64::from(low) | (u64::from(high) << 32);
    }
}
