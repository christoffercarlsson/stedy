use core::{
    ptr,
    sync::atomic::{compiler_fence, Ordering},
};

#[inline(never)]
pub fn wipe<T: Copy + Default>(data: &mut [T]) {
    let p = data.as_mut_ptr();
    for i in 0..data.len() {
        unsafe {
            ptr::write_volatile(p.add(i), T::default());
        }
    }
    compiler_fence(Ordering::SeqCst);
}

pub(crate) trait Wipe {
    fn wipe(&mut self);
}

pub(crate) trait Primitive: Copy + Default {}

impl Primitive for u8 {}
impl Primitive for i8 {}
impl Primitive for u16 {}
impl Primitive for i16 {}
impl Primitive for u32 {}
impl Primitive for i32 {}
impl Primitive for u64 {}
impl Primitive for i64 {}
impl Primitive for u128 {}
impl Primitive for usize {}

impl<T: Primitive, const N: usize> Wipe for [T; N] {
    fn wipe(&mut self) {
        wipe(self);
    }
}

impl<T: Primitive, const M: usize, const N: usize> Wipe for [[T; M]; N] {
    fn wipe(&mut self) {
        wipe(self.as_flattened_mut());
    }
}

#[cfg(feature = "std")]
impl<T: Wipe> Wipe for Vec<T> {
    fn wipe(&mut self) {
        for item in self.iter_mut() {
            item.wipe();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wipe() {
        let mut data = [
            80, 140, 94, 140, 50, 124, 20, 226, 225, 167, 43, 163, 78, 235, 69, 47, 55, 69, 139,
            32, 158, 214, 58, 41, 77, 153, 155, 76, 134, 103, 89, 130,
        ];
        wipe(&mut data);
        assert_eq!(data, [0u8; 32]);
    }
}
