#[inline]
pub fn declassify<T>(value: T) -> T
where
    T: Copy,
{
    #[cfg(all(
        stedy_ct_check,
        any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")
    ))]
    let value = {
        let mut value = value;
        valgrind::make_mem_defined(core::ptr::from_mut(&mut value).cast(), size_of::<T>());
        value
    };
    value
}

#[inline]
pub fn declassify_slice<T>(values: &[T]) {
    #[cfg(all(
        stedy_ct_check,
        any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")
    ))]
    valgrind::make_mem_defined(values.as_ptr().cast(), size_of_val(values));
    let _ = values;
}

#[cfg(all(
    stedy_ct_check,
    any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")
))]
#[allow(unsafe_code)]
mod valgrind {
    const MAKE_MEM_DEFINED: usize = 0x4d43_0002;

    #[cfg(target_arch = "aarch64")]
    pub fn make_mem_defined(address: *const u8, size: usize) {
        let request = [MAKE_MEM_DEFINED, address as usize, size, 0, 0, 0];
        unsafe {
            core::arch::asm!(
                "ror x12, x12, #3",
                "ror x12, x12, #13",
                "ror x12, x12, #51",
                "ror x12, x12, #61",
                "orr x10, x10, x10",
                inout("x3") 0usize => _,
                in("x4") request.as_ptr(),
                options(nostack),
            );
        }
    }

    #[cfg(target_arch = "x86")]
    pub fn make_mem_defined(address: *const u8, size: usize) {
        let request = [MAKE_MEM_DEFINED, address as usize, size, 0, 0, 0];
        unsafe {
            core::arch::asm!(
                "rol edi, 3",
                "rol edi, 13",
                "rol edi, 29",
                "rol edi, 19",
                "xchg ebx, ebx",
                inout("edx") 0usize => _,
                in("eax") request.as_ptr(),
                options(nostack),
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn make_mem_defined(address: *const u8, size: usize) {
        let request = [MAKE_MEM_DEFINED, address as usize, size, 0, 0, 0];
        unsafe {
            core::arch::asm!(
                "rol rdi, 3",
                "rol rdi, 13",
                "rol rdi, 61",
                "rol rdi, 51",
                "xchg rbx, rbx",
                inout("rdx") 0usize => _,
                in("rax") request.as_ptr(),
                options(nostack),
            );
        }
    }
}
