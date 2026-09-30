#![allow(non_snake_case)]
use {
    crate::{
        elliptic_curves::Edwards,
        traits::{ByteArray, CryptoRng, EdwardsParams, EdwardsScalar, FieldElement, Hasher},
        Secret,
    },
    core::marker::PhantomData,
};

pub struct Eddsa<E, F, H, S>
where
    E: EdwardsScalar,
    F: FieldElement + EdwardsParams<F>,
    H: Hasher<Output = E::WideBytes>,
    S: ByteArray,
{
    _marker: PhantomData<(E, F, H, S)>,
}

impl<E, F, H, S> Eddsa<E, F, H, S>
where
    E: EdwardsScalar,
    F: FieldElement + EdwardsParams<F>,
    H: Hasher<Output = E::WideBytes>,
    S: ByteArray,
{
    pub fn generate_key_pair(rng: &mut impl CryptoRng) -> (S, F::Bytes) {
        let mut seed = Secret::<E::SecretBytes>::new();
        rng.fill(seed.get_mut().as_mut());
        Self::key_pair(seed.get())
    }

    pub fn key_pair(seed: &E::SecretBytes) -> (S, F::Bytes) {
        let (a, _) = Self::expand(seed.as_ref());
        let public_key = Edwards::<F, E>::mul_base(&a).compress();
        let mut private_key = S::new();
        let (s, A) = Self::private_key_components_mut(&mut private_key)
            .expect("Private key size is correct");
        s.copy_from_slice(seed.as_ref());
        A.copy_from_slice(public_key.as_ref());
        (private_key, public_key)
    }

    pub fn public_key(private_key: &S) -> F::Bytes {
        let (_, A) = Self::read_private_key(private_key);
        F::Bytes::from_slice(A)
    }

    pub fn sign(private_key: &S, message: &[u8]) -> S {
        let (seed, A) = Self::read_private_key(private_key);
        let (a, prefix) = Self::expand(seed);
        let mut state = H::new();
        state.update(prefix.get().as_ref());
        state.update(message);
        let r = E::from(state.finalize());
        let R = Edwards::<F, E>::mul_base(&r).compress();
        let mut state = H::new();
        state.update(R.as_ref());
        state.update(A);
        state.update(message);
        let k = E::from(state.finalize());
        let s: E::Bytes = (r + k * a).into();
        Self::create_signature(&R, &s)
    }

    pub fn verify(message: &[u8], public_key: &F::Bytes, signature: &S) -> bool {
        let (r, s) = Self::read_signature(signature);
        let valid_s = E::is_canonical(&s);
        let (A, valid_a) = Edwards::<F, E>::decompress(public_key);
        let (R, valid_r) = Edwards::<F, E>::decompress(&r);
        let mut state = H::new();
        state.update(r.as_ref());
        state.update(public_key.as_ref());
        state.update(message);
        let k = E::from(state.finalize());
        let s = E::from(s);
        let r2 = Edwards::<F, E>::vartime_double_base(&k.neg(), A, &s);
        (r2.ct_eq(&R) & valid_a & valid_r & valid_s).to_bool()
    }
}

impl<E, F, H, S> Eddsa<E, F, H, S>
where
    E: EdwardsScalar,
    F: FieldElement + EdwardsParams<F>,
    H: Hasher<Output = E::WideBytes>,
    S: ByteArray,
{
    const SEED_SIZE: usize = E::SecretBytes::SIZE;

    fn expand(seed: &[u8]) -> (E, Secret<E::SecretBytes>) {
        let digest = Secret::from(H::digest(seed));
        let (a, prefix) = E::split(digest.get());
        let mut a = Secret::from(a);
        E::clamp(a.get_mut());
        (E::from(*a.get()), Secret::from(prefix))
    }

    fn private_key_components_mut(private_key: &mut S) -> Option<(&mut [u8], &mut [u8])> {
        let (seed, public_key) = private_key.as_mut().split_at_mut_checked(Self::SEED_SIZE)?;
        (public_key.len() == F::Bytes::SIZE).then_some((seed, public_key))
    }

    fn read_private_key(private_key: &S) -> (&[u8], &[u8]) {
        private_key.as_ref().split_at(Self::SEED_SIZE)
    }

    fn create_signature(r_bytes: &F::Bytes, s_bytes: &E::Bytes) -> S {
        let mut signature = S::new();
        let (r, s) =
            Self::signature_from_components_mut(&mut signature).expect("Signature size is correct");
        r.copy_from_slice(r_bytes.as_ref());
        s.copy_from_slice(s_bytes.as_ref());
        signature
    }

    fn signature_from_components_mut(signature: &mut S) -> Option<(&mut [u8], &mut [u8])> {
        let (r, s) = signature.as_mut().split_at_mut_checked(F::Bytes::SIZE)?;
        (s.len() == E::Bytes::SIZE).then_some((r, s))
    }

    fn read_signature(signature: &S) -> (F::Bytes, E::Bytes) {
        let (r, s) = signature.as_ref().split_at(F::Bytes::SIZE);
        let r = F::Bytes::from_slice(r);
        let s = E::Bytes::from_slice(s);
        (r, s)
    }
}
