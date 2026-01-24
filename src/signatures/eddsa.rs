#![allow(non_snake_case)]
use {
    crate::traits::{ByteArray, CryptoRng, EdwardsPoint, Hasher, Scalar},
    core::marker::PhantomData,
};

pub struct Eddsa<H, P, S, const SIGNATURE_SIZE: usize>
where
    H: Hasher<Output = S::WideBytes>,
    P: EdwardsPoint<S>,
    S: Scalar,
{
    _marker: PhantomData<(H, P, S)>,
}

impl<H, P, S, const SIGNATURE_SIZE: usize> Eddsa<H, P, S, SIGNATURE_SIZE>
where
    H: Hasher<Output = S::WideBytes>,
    P: EdwardsPoint<S>,
    S: Scalar,
{
    pub fn generate_key_pair(rng: &mut impl CryptoRng) -> (S::Bytes, P::Bytes) {
        let mut private_key = S::Bytes::new();
        rng.fill(private_key.as_mut());
        let public_key = Self::public_key(&private_key);
        (private_key, public_key)
    }

    pub fn public_key(private_key: &S::Bytes) -> P::Bytes {
        let g = P::BASE_POINT;
        let (a, _) = Self::expand(private_key);
        (g * a).compress()
    }

    pub fn sign(private_key: &S::Bytes, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
        let B = P::BASE_POINT;
        let (a, prefix) = Self::expand(private_key);
        let A = (B * a).compress();
        let mut state = H::new();
        state.update(prefix.as_ref());
        state.update(message);
        let r = S::from(state.finalize());
        let R = (B * r).compress();
        let mut state = H::new();
        state.update(R.as_ref());
        state.update(A.as_ref());
        state.update(message);
        let k = S::from(state.finalize());
        let s: S::Bytes = (r + k * a).into();
        Self::create_signature(&R, &s)
    }

    pub fn verify(message: &[u8], public_key: &P::Bytes, signature: &[u8; SIGNATURE_SIZE]) -> bool {
        let (r, s) = Self::read_signature(signature);
        let (A, valid_a) = P::decompress(public_key);
        let (R, valid_r) = P::decompress(r);
        let mut state = H::new();
        state.update(r.as_ref());
        state.update(public_key.as_ref());
        state.update(message);
        let k = S::from(state.finalize());
        let s = S::from(*s);
        let r2 = P::vartime_double_base(&k.neg(), A, &s);
        let verified = (r2 == R) as u64;
        (verified & valid_a & valid_r) == 1
    }
}

impl<H, P, S, const SIGNATURE_SIZE: usize> Eddsa<H, P, S, SIGNATURE_SIZE>
where
    H: Hasher<Output = S::WideBytes>,
    P: EdwardsPoint<S>,
    S: Scalar,
{
    const POINT_BYTES_SIZE: usize = size_of::<P::Bytes>();

    fn expand(private_key: &S::Bytes) -> (S, S::Bytes) {
        let digest = H::digest(private_key.as_ref());
        let (a, prefix) = S::split(&digest);
        let mut a = *a;
        S::clamp(&mut a);
        (S::from(a), *prefix)
    }

    fn create_signature(r_bytes: &P::Bytes, s_bytes: &S::Bytes) -> [u8; SIGNATURE_SIZE] {
        let mut signature = [0u8; SIGNATURE_SIZE];
        let (r, s) =
            Self::signature_from_components_mut(&mut signature).expect("SIGNATURE_SIZE is correct");
        r.as_mut().copy_from_slice(r_bytes.as_ref());
        s.as_mut().copy_from_slice(s_bytes.as_ref());
        signature
    }

    fn signature_from_components_mut(
        signature: &mut [u8; SIGNATURE_SIZE],
    ) -> Option<(&mut P::Bytes, &mut S::Bytes)> {
        let (r, s) = signature.split_at_mut_checked(Self::POINT_BYTES_SIZE)?;
        let r = P::Bytes::from_slice_mut_checked(r)?;
        let s = S::Bytes::from_slice_mut_checked(s)?;
        Some((r, s))
    }

    fn read_signature(signature: &[u8; SIGNATURE_SIZE]) -> (&P::Bytes, &S::Bytes) {
        let (r, s) = signature.split_at(Self::POINT_BYTES_SIZE);
        let r = P::Bytes::from_slice(r);
        let s = S::Bytes::from_slice(s);
        (r, s)
    }
}
