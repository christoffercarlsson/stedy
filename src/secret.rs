use {
    crate::utils::Wipe,
    core::ops::{Index, IndexMut},
};

#[allow(private_bounds)]
pub struct Secret<T: Wipe>(pub(crate) T);

#[allow(private_bounds)]
impl<T: Wipe> Secret<T> {
    pub fn get(&self) -> &T {
        &self.0
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Wipe + Default> Default for Secret<T> {
    fn default() -> Self {
        Self(T::default())
    }
}

impl<T: Wipe + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Wipe> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

impl<T, I> Index<I> for Secret<T>
where
    T: Wipe + Index<I>,
{
    type Output = T::Output;

    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl<T, I> IndexMut<I> for Secret<T>
where
    T: Wipe + IndexMut<I>,
{
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<T: Wipe> From<T> for Secret<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

impl<const N: usize> AsRef<[i8]> for Secret<[i8; N]> {
    fn as_ref(&self) -> &[i8] {
        &self.0
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

pub(crate) type SecretDigits<const N: usize> = Secret<[i8; N]>;
