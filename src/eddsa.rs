use {
    crate::traits::{ByteArray, CryptoRng, EdwardsPoint, FieldElement, Hasher, Init, Scalar},
    core::marker::PhantomData,
};

pub struct Eddsa<F: FieldElement, H: Hasher, P: EdwardsPoint<F, S>, S: Scalar> {
    _f: PhantomData<F>,
    _h: PhantomData<H>,
    _p: PhantomData<P>,
    _s: PhantomData<S>,
}

impl<F: FieldElement, H: Hasher, P: EdwardsPoint<F, S>, S: Scalar> Eddsa<F, H, P, S> {
    pub fn generate_key_pair<R: CryptoRng>(rng: &mut R) -> (S::Bytes, S::Bytes) {
        let mut private_key = S::Bytes::new();
        rng.fill(private_key.as_mut());
        let public_key = Self::get_public_key(&private_key);
        (private_key, public_key)
    }

    pub fn get_public_key(private_key: &S::Bytes) -> S::Bytes {
        let g = P::BASE_POINT;
        let (a, _) = Self::expand(private_key);
        (g * a).compress()
    }

    pub fn sign(private_key: &S::Bytes, message: &[u8]) -> S::WideBytes {
        let g = P::BASE_POINT;
        let (a, prefix) = Self::expand(private_key);
        let ga = (g * a).compress();
        let mut state = H::new();
        state.update(prefix.as_ref());
        state.update(message);
        let r = Self::scalar_from_state(state);
        let gr = (g * r).compress();
        let mut state = H::new();
        state.update(gr.as_ref());
        state.update(ga.as_ref());
        state.update(message);
        let h = Self::scalar_from_state(state);
        let s: S::Bytes = (r + h * a).into();
        S::concat(&gr, &s)
    }

    pub fn verify(message: &[u8], public_key: &S::Bytes, signature: &S::WideBytes) -> bool {
        let (gr, s) = S::split(signature);
        let s = S::from(*s);
        let (a, valid_a) = P::decompress(public_key);
        let (r, valid_r) = P::decompress(gr);
        let mut state = H::new();
        state.update(gr.as_ref());
        state.update(public_key.as_ref());
        state.update(message);
        let h = Self::scalar_from_state(state);
        let r2 = P::vartime_double_base(&h.neg(), a, &s);
        let verified = (r2 == r) as u64;
        (verified & valid_a & valid_r) == 1
    }
}

impl<F: FieldElement, H: Hasher, P: EdwardsPoint<F, S>, S: Scalar> Eddsa<F, H, P, S> {
    fn expand(private_key: &S::Bytes) -> (S, S::Bytes) {
        let mut hasher = H::new();
        hasher.update(private_key.as_ref());
        let digest = hasher.finalize();
        let bytes = S::WideBytes::from_slice(digest.as_ref());
        let (a, prefix) = S::split(bytes);
        let mut a = *a;
        let prefix = *prefix;
        S::clamp(&mut a);
        (S::from(a), prefix)
    }

    fn scalar_from_state(state: H) -> S {
        let digest = state.finalize();
        let bytes = S::WideBytes::from_slice(digest.as_ref());
        S::from(*bytes)
    }
}
