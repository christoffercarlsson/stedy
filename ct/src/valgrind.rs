#![allow(unsafe_code)]

const RUNNING_ON_VALGRIND: usize = 0x1001;
const MAKE_MEM_UNDEFINED: usize = 0x4d43_0001;
const MAKE_MEM_DEFINED: usize = 0x4d43_0002;

pub fn running() -> bool {
    request(RUNNING_ON_VALGRIND, 0, 0) != 0
}

pub fn classify<T: ?Sized>(value: &T) {
    request_for(MAKE_MEM_UNDEFINED, value);
}

pub fn declassify<T: ?Sized>(value: &T) {
    request_for(MAKE_MEM_DEFINED, value);
}

fn request_for<T: ?Sized>(code: usize, value: &T) {
    request(
        code,
        core::ptr::from_ref(value).cast::<u8>() as usize,
        size_of_val(value),
    );
}

#[cfg(target_arch = "aarch64")]
fn request(code: usize, address: usize, size: usize) -> usize {
    let args = [code, address, size, 0, 0, 0];
    let result;
    unsafe {
        core::arch::asm!(
            "ror x12, x12, #3",
            "ror x12, x12, #13",
            "ror x12, x12, #51",
            "ror x12, x12, #61",
            "orr x10, x10, x10",
            inout("x3") 0usize => result,
            in("x4") args.as_ptr(),
            options(nostack),
        );
    }
    result
}

#[cfg(target_arch = "x86")]
fn request(code: usize, address: usize, size: usize) -> usize {
    let args = [code, address, size, 0, 0, 0];
    let result;
    unsafe {
        core::arch::asm!(
            "rol edi, 3",
            "rol edi, 13",
            "rol edi, 29",
            "rol edi, 19",
            "xchg ebx, ebx",
            inout("edx") 0usize => result,
            in("eax") args.as_ptr(),
            options(nostack),
        );
    }
    result
}

#[cfg(target_arch = "x86_64")]
fn request(code: usize, address: usize, size: usize) -> usize {
    let args = [code, address, size, 0, 0, 0];
    let result;
    unsafe {
        core::arch::asm!(
            "rol rdi, 3",
            "rol rdi, 13",
            "rol rdi, 61",
            "rol rdi, 51",
            "xchg rbx, rbx",
            inout("rdx") 0usize => result,
            in("rax") args.as_ptr(),
            options(nostack),
        );
    }
    result
}
