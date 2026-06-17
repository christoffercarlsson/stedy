#![allow(non_snake_case)]
use {
    crate::{
        elliptic_curves::Edwards,
        traits::{ByteArray, CryptoRng, EdwardsParams, EdwardsScalar, FieldElement, Hasher},
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
    pub fn generate_key_pair(rng: &mut impl CryptoRng) -> (E::Bytes, F::Bytes) {
        let mut private_key = E::Bytes::new();
        rng.fill(private_key.as_mut());
        let public_key = Self::public_key(&private_key);
        (private_key, public_key)
    }

    pub fn public_key(private_key: &E::Bytes) -> F::Bytes {
        let g = Edwards::<F, E>::BASE_POINT;
        let (a, _) = Self::expand(private_key);
        (g * a).compress()
    }

    pub fn sign(private_key: &E::Bytes, message: &[u8]) -> S {
        let B = Edwards::<F, E>::BASE_POINT;
        let (a, prefix) = Self::expand(private_key);
        let A = (B * a).compress();
        let mut state = H::new();
        state.update(prefix.as_ref());
        state.update(message);
        let r = E::from(state.finalize());
        let R = (B * r).compress();
        let mut state = H::new();
        state.update(R.as_ref());
        state.update(A.as_ref());
        state.update(message);
        let k = E::from(state.finalize());
        let s: E::Bytes = (r + k * a).into();
        Self::create_signature(&R, &s)
    }

    pub fn verify(message: &[u8], public_key: &F::Bytes, signature: &S) -> bool {
        let (r, s) = Self::read_signature(signature);
        let (A, valid_a) = Edwards::<F, E>::decompress(public_key);
        let (R, valid_r) = Edwards::<F, E>::decompress(r);
        let mut state = H::new();
        state.update(r.as_ref());
        state.update(public_key.as_ref());
        state.update(message);
        let k = E::from(state.finalize());
        let s = E::from(*s);
        let r2 = Edwards::<F, E>::vartime_double_base(&k.neg(), A, &s);
        let verified = (r2 == R) as u64;
        (verified & valid_a & valid_r) == 1
    }
}

impl<E, F, H, S> Eddsa<E, F, H, S>
where
    E: EdwardsScalar,
    F: FieldElement + EdwardsParams<F>,
    H: Hasher<Output = E::WideBytes>,
    S: ByteArray,
{
    const POINT_BYTES_SIZE: usize = size_of::<F::Bytes>();

    fn expand(private_key: &E::Bytes) -> (E, E::Bytes) {
        let digest = H::digest(private_key.as_ref());
        let (a, prefix) = E::split(&digest);
        let mut a = *a;
        E::clamp(&mut a);
        (E::from(a), *prefix)
    }

    fn create_signature(r_bytes: &F::Bytes, s_bytes: &E::Bytes) -> S {
        let mut signature = S::new();
        let (r, s) =
            Self::signature_from_components_mut(&mut signature).expect("Signature size is correct");
        r.as_mut().copy_from_slice(r_bytes.as_ref());
        s.as_mut().copy_from_slice(s_bytes.as_ref());
        signature
    }

    fn signature_from_components_mut(signature: &mut S) -> Option<(&mut F::Bytes, &mut E::Bytes)> {
        let (r, s) = signature
            .as_mut()
            .split_at_mut_checked(Self::POINT_BYTES_SIZE)?;
        let r = F::Bytes::from_slice_mut_checked(r)?;
        let s = E::Bytes::from_slice_mut_checked(s)?;
        Some((r, s))
    }

    fn read_signature(signature: &S) -> (&F::Bytes, &E::Bytes) {
        let (r, s) = signature.as_ref().split_at(Self::POINT_BYTES_SIZE);
        let r = F::Bytes::from_slice(r);
        let s = E::Bytes::from_slice(s);
        (r, s)
    }
}
