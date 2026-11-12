use {
    crate::traits::Wipe,
    core::{
        fmt::{self, Debug, Formatter},
        ops::{Deref, DerefMut},
    },
};

pub struct Secret<T>(T)
where
    T: Wipe;

impl<T> Secret<T>
where
    T: Wipe,
{
    pub fn get(&self) -> &T {
        &self.0
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> Default for Secret<T>
where
    T: Wipe + Default,
{
    fn default() -> Self {
        Self(T::default())
    }
}

impl<T> Clone for Secret<T>
where
    T: Wipe + Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }

    fn clone_from(&mut self, source: &Self) {
        self.0.wipe();
        self.0.clone_from(&source.0);
    }
}

impl<T> Debug for Secret<T>
where
    T: Wipe,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl<T> Drop for Secret<T>
where
    T: Wipe,
{
    fn drop(&mut self) {
        self.0.wipe();
    }
}

impl<T> Deref for Secret<T>
where
    T: Wipe,
{
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Secret<T>
where
    T: Wipe,
{
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> From<T> for Secret<T>
where
    T: Wipe,
{
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

impl<T, U> AsRef<U> for Secret<T>
where
    T: Wipe + AsRef<U>,
    U: ?Sized,
{
    fn as_ref(&self) -> &U {
        self.0.as_ref()
    }
}

impl<T, U> AsMut<U> for Secret<T>
where
    T: Wipe + AsMut<U>,
    U: ?Sized,
{
    fn as_mut(&mut self) -> &mut U {
        self.0.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_clone_from() {
        let mut secret = Secret::from([1u8; 4]);
        secret.clone_from(&Secret::from([2u8; 4]));
        assert_eq!(*secret, [2u8; 4]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_secret_debug() {
        assert_eq!(format!("{:?}", Secret::from([1u8; 4])), "Secret(..)");
    }
}
