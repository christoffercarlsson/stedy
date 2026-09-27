use {super::Backend, core::arch::asm};

pub(super) fn opaque(mut value: u32) -> u32 {
    unsafe {
        asm!("/* {0:w} */", inout(reg) value, options(pure, nomem, nostack, preserves_flags));
    }
    value
}

impl Backend for u32 {
    fn assign(dst: &mut Self, src: Self, condition: u8) {
        unsafe {
            asm!(
                "tst {condition:w}, 0xff",
                "csel {dst:w}, {src:w}, {dst:w}, ne",
                condition = in(reg) u32::from(condition),
                dst = inout(reg) *dst,
                src = in(reg) src,
                options(pure, nomem, nostack),
            );
        }
    }
}

impl Backend for u64 {
    fn assign(dst: &mut Self, src: Self, condition: u8) {
        unsafe {
            asm!(
                "tst {condition:w}, 0xff",
                "csel {dst:x}, {src:x}, {dst:x}, ne",
                condition = in(reg) u32::from(condition),
                dst = inout(reg) *dst,
                src = in(reg) src,
                options(pure, nomem, nostack),
            );
        }
    }
}
