use {
    crate::{
        Error,
        traits::{CryptoRng, EllipticCurve},
        utils::Secret,
    },
    core::marker::PhantomData,
};

pub struct Ecdh<C>
where
    C: EllipticCurve,
{
    _marker: PhantomData<C>,
}

impl<C> Ecdh<C>
where
    C: EllipticCurve,
{
    pub(crate) fn generate_key_pair(
        rng: &mut impl CryptoRng,
        private_key: &mut C::ScalarBytes,
    ) -> Result<C::PointBytes, Error> {
        loop {
            rng.fill(private_key.as_mut())?;
            if let Ok(public_key) = Self::public_key(private_key) {
                return Ok(public_key);
            }
        }
    }

    pub(crate) fn public_key(private_key: &C::ScalarBytes) -> Result<C::PointBytes, Error> {
        let scalar = C::scalar_from_bytes(private_key)?;
        let point = C::scalar_mult_base(&scalar);
        Ok(C::point_to_bytes(&point))
    }

    pub(crate) fn key_exchange(
        private_key: &C::ScalarBytes,
        public_key: &C::PointBytes,
        shared_secret: &mut C::SharedSecretBytes,
    ) -> Result<(), Error> {
        let scalar = C::scalar_from_bytes(private_key)?;
        let point = C::point_from_bytes(public_key)?;
        let product = Secret::from(C::scalar_mult(&scalar, &point)?);
        *shared_secret = C::shared_secret_bytes(product.get());
        Ok(())
    }
}
