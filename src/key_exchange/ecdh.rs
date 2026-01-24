use {
    crate::traits::{CryptoRng, Curve},
    core::marker::PhantomData,
};

pub struct Ecdh<C: Curve> {
    _c: PhantomData<C>,
}

impl<C: Curve> Ecdh<C> {
    pub fn generate_key_pair(rng: &mut impl CryptoRng) -> (C::ScalarBytes, C::PointBytes) {
        let scalar = C::generate_scalar(rng);
        let point = C::scalar_mult_base(&scalar);
        let private_key = C::scalar_to_bytes(&scalar);
        let public_key = C::point_to_bytes(&point);
        (private_key, public_key)
    }

    pub fn public_key(private_key: &C::ScalarBytes) -> Option<C::PointBytes> {
        let scalar = C::scalar_from_bytes(private_key)?;
        let point = C::scalar_mult_base(&scalar);
        let public_key = C::point_to_bytes(&point);
        Some(public_key)
    }

    pub fn key_exchange(
        private_key: &C::ScalarBytes,
        public_key: &C::PointBytes,
    ) -> Option<C::PointBytes> {
        let scalar = C::scalar_from_bytes(private_key)?;
        let point = C::point_from_bytes(public_key)?;
        let shared_secret = C::scalar_mult(&scalar, &point)?;
        Some(C::point_to_bytes(&shared_secret))
    }
}
