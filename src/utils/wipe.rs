#![allow(unsafe_code)]
use {
    crate::traits::{Wipe, ZeroDefault},
    core::{
        mem::{align_of, size_of, size_of_val},
        ptr,
        sync::atomic::{Ordering, compiler_fence},
    },
};

#[inline]
#[allow(clippy::cast_ptr_alignment)]
pub fn wipe<T>(data: &mut [T])
where
    T: ZeroDefault,
{
    let size = size_of_val(data);
    let bytes = data.as_mut_ptr().cast::<u8>();
    let head = bytes.align_offset(align_of::<usize>()).min(size);
    let words = (size - head) / size_of::<usize>();
    let tail = head + words * size_of::<usize>();
    unsafe {
        for i in 0..head {
            ptr::write_volatile(bytes.add(i), 0);
        }
        let aligned = bytes.add(head).cast::<usize>();
        for i in 0..words {
            ptr::write_volatile(aligned.add(i), 0);
        }
        for i in tail..size {
            ptr::write_volatile(bytes.add(i), 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

impl ZeroDefault for u8 {}
impl ZeroDefault for u16 {}
impl ZeroDefault for u32 {}
impl ZeroDefault for u64 {}
impl ZeroDefault for u128 {}
impl ZeroDefault for usize {}
impl ZeroDefault for i8 {}
impl ZeroDefault for i16 {}
impl ZeroDefault for i32 {}
impl ZeroDefault for i64 {}
impl ZeroDefault for i128 {}
impl ZeroDefault for isize {}
impl ZeroDefault for bool {}
impl ZeroDefault for char {}

impl<T> Wipe for T
where
    T: ZeroDefault,
{
    fn wipe(&mut self) {
        unsafe {
            ptr::write_volatile(self, T::default());
        }
        compiler_fence(Ordering::SeqCst);
    }

    fn wipe_slice(slice: &mut [Self]) {
        wipe(slice);
    }
}

impl<T, const N: usize> Wipe for [T; N]
where
    T: Wipe,
{
    fn wipe(&mut self) {
        T::wipe_slice(self);
    }

    fn wipe_slice(slice: &mut [Self]) {
        T::wipe_slice(slice.as_flattened_mut());
    }
}

impl<T> Wipe for Option<T>
where
    T: Wipe,
{
    fn wipe(&mut self) {
        if let Some(value) = self {
            value.wipe();
        }
        unsafe {
            ptr::write_volatile(self, None);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(feature = "std")]
impl<T> Wipe for Vec<T>
where
    T: Wipe,
{
    fn wipe(&mut self) {
        T::wipe_slice(self);
        self.clear();
        let spare = self.spare_capacity_mut();
        let p = spare.as_mut_ptr().cast::<u8>();
        for i in 0..size_of_val(spare) {
            unsafe {
                ptr::write_volatile(p.add(i), 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(feature = "std")]
impl<T> Wipe for Box<[T]>
where
    T: Wipe,
{
    fn wipe(&mut self) {
        T::wipe_slice(self);
    }
}

#[cfg(feature = "std")]
impl Wipe for String {
    fn wipe(&mut self) {
        unsafe { self.as_mut_vec() }.wipe();
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

    #[test]
    fn test_wipe_unaligned() {
        let mut data = [255u8; 40];
        wipe(&mut data[1..38]);
        assert_eq!(data[0], 255);
        assert!(data[1..38].iter().all(|&byte| byte == 0));
        assert_eq!(data[38..], [255, 255]);
    }

    #[test]
    fn test_wipe_array() {
        let mut data = [[7i32; 4]; 3];
        data.wipe();
        assert_eq!(data, [[0; 4]; 3]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_wipe_vec() {
        let mut data = vec![9u8; 16];
        data.truncate(4);
        data.wipe();
        unsafe { data.set_len(16) };
        assert_eq!(data, [0; 16]);
    }

    #[test]
    fn test_wipe_option() {
        let mut data = Some([5u8; 8]);
        data.wipe();
        assert_eq!(data, None);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_wipe_heap() {
        let mut vec = vec![[3u16; 2]; 4];
        vec.wipe();
        assert_eq!(vec, [] as [[u16; 2]; 0]);
        let mut string = String::from("password");
        string.wipe();
        assert_eq!(string, "");
        let mut boxed: Box<[u32]> = Box::new([1, 2, 3]);
        boxed.wipe();
        assert_eq!(*boxed, [0, 0, 0]);
    }
}
