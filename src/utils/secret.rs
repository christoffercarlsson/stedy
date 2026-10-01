use {
    super::wipe,
    core::{
        mem::size_of,
        ops::{Index, IndexMut},
        ptr, slice,
    },
};

pub(crate) struct Secret<T: Copy>(pub(crate) T);

impl<T: Copy> Secret<T> {
    pub(crate) fn get(&self) -> &T {
        &self.0
    }

    pub(crate) fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Copy + Default> Default for Secret<T> {
    fn default() -> Self {
        Self(T::default())
    }
}

impl<T: Copy> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<T: Copy> Drop for Secret<T> {
    fn drop(&mut self) {
        let bytes = ptr::from_mut(&mut self.0).cast::<u8>();
        let bytes = unsafe { slice::from_raw_parts_mut(bytes, size_of::<T>()) };
        let (head, words, tail) = unsafe { bytes.align_to_mut::<usize>() };
        wipe(head);
        wipe(words);
        wipe(tail);
    }
}

impl<T, I> Index<I> for Secret<T>
where
    T: Copy + Index<I>,
{
    type Output = T::Output;

    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl<T, I> IndexMut<I> for Secret<T>
where
    T: Copy + IndexMut<I>,
{
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<T: Copy> From<T> for Secret<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

impl<const N: usize> AsRef<[u8]> for Secret<[u8; N]> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for Secret<[u8; N]> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
