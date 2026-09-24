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

impl<T: Copy + Default, const N: usize> Wipe for [T; N] {
    fn wipe(&mut self) {
        wipe(self);
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
