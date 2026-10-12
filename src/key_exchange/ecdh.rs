use {
    crate::{
        Error,
        traits::{CryptoRng, EllipticCurve},
    },
    core::marker::PhantomData,
};

pub struct Ecdh<C: EllipticCurve> {
    _marker: PhantomData<C>,
}

impl<C: EllipticCurve> Ecdh<C> {
    pub fn generate_key_pair(
        rng: &mut impl CryptoRng,
    ) -> Result<(C::ScalarBytes, C::PointBytes), Error> {
        let scalar = C::generate_scalar(rng)?;
        let point = C::scalar_mult_base(&scalar);
        let private_key = C::scalar_to_bytes(&scalar);
        let public_key = C::point_to_bytes(&point);
        Ok((private_key, public_key))
    }

    pub fn public_key(private_key: &C::ScalarBytes) -> Result<C::PointBytes, Error> {
        let scalar = C::scalar_from_bytes(private_key)?;
        let point = C::scalar_mult_base(&scalar);
        Ok(C::point_to_bytes(&point))
    }

    pub fn key_exchange(
        private_key: &C::ScalarBytes,
        public_key: &C::PointBytes,
    ) -> Result<C::SharedSecretBytes, Error> {
        let scalar = C::scalar_from_bytes(private_key)?;
        let point = C::point_from_bytes(public_key)?;
        let shared_secret = C::scalar_mult(&scalar, &point)?;
        Ok(C::shared_secret_bytes(&shared_secret))
    }
}
