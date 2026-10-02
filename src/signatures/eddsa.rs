#![allow(non_snake_case)]
use {
    crate::{
        elliptic_curves::Edwards,
        traits::{ByteArray, CryptoRng, EdwardsParams, EdwardsScalar, FieldElement, Hasher},
        utils::Secret,
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
        let mut seed = Secret::from(E::SecretBytes::new());
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
        Self::sign_message(private_key, 0, &[], message)
    }

    pub fn verify(message: &[u8], public_key: &F::Bytes, signature: &S) -> bool {
        Self::verify_message(0, &[], message, public_key, signature)
    }
}

pub struct HashEddsa<E, F, H, S, P>
where
    E: EdwardsScalar,
    F: FieldElement + EdwardsParams<F>,
    H: Hasher<Output = E::WideBytes>,
    S: ByteArray,
    P: Hasher,
{
    prehash: P,
    _marker: PhantomData<(E, F, H, S)>,
}

impl<E, F, H, S, P> HashEddsa<E, F, H, S, P>
where
    E: EdwardsScalar,
    F: FieldElement + EdwardsParams<F>,
    H: Hasher<Output = E::WideBytes>,
    S: ByteArray,
    P: Hasher,
{
    pub fn new() -> Self {
        Self {
            prehash: P::new(),
            _marker: PhantomData,
        }
    }

    pub fn update(&mut self, message: &[u8]) {
        self.prehash.update(message);
    }

    pub fn sign(self, private_key: &S, context: &[u8]) -> Option<S> {
        u8::try_from(context.len()).ok()?;
        let digest = self.prehash.finalize();
        Some(Eddsa::<E, F, H, S>::sign_message(
            private_key,
            1,
            context,
            digest.as_ref(),
        ))
    }

    pub fn verify(self, context: &[u8], public_key: &F::Bytes, signature: &S) -> bool {
        if u8::try_from(context.len()).is_err() {
            return false;
        }
        let digest = self.prehash.finalize();
        Eddsa::<E, F, H, S>::verify_message(1, context, digest.as_ref(), public_key, signature)
    }
}

impl<E, F, H, S, P> Default for HashEddsa<E, F, H, S, P>
where
    E: EdwardsScalar,
    F: FieldElement + EdwardsParams<F>,
    H: Hasher<Output = E::WideBytes>,
    S: ByteArray,
    P: Hasher,
{
    fn default() -> Self {
        Self::new()
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

    fn sign_message(private_key: &S, phflag: u8, context: &[u8], message: &[u8]) -> S {
        let (seed, A) = Self::read_private_key(private_key);
        let (a, prefix) = Self::expand(seed);
        let mut state = Self::hasher(phflag, context);
        state.update(prefix.get().as_ref());
        state.update(message);
        let r = E::from(state.finalize());
        let R = Edwards::<F, E>::mul_base(&r).compress();
        let mut state = Self::hasher(phflag, context);
        state.update(R.as_ref());
        state.update(A);
        state.update(message);
        let k = E::from(state.finalize());
        let s: E::Bytes = (r + k * a).into();
        Self::create_signature(&R, &s)
    }

    fn verify_message(
        phflag: u8,
        context: &[u8],
        message: &[u8],
        public_key: &F::Bytes,
        signature: &S,
    ) -> bool {
        let (r, s) = Self::read_signature(signature);
        let valid_s = E::is_canonical(&s);
        let (A, valid_a) = Edwards::<F, E>::decompress(public_key);
        let (R, valid_r) = Edwards::<F, E>::decompress(&r);
        let mut state = Self::hasher(phflag, context);
        state.update(r.as_ref());
        state.update(public_key.as_ref());
        state.update(message);
        let k = E::from(state.finalize());
        let s = E::from(s);
        let r2 = Edwards::<F, E>::vartime_double_base(&k.neg(), A, &s);
        (r2.ct_eq(&R) & valid_a & valid_r & valid_s).to_bool()
    }

    fn hasher(phflag: u8, context: &[u8]) -> H {
        let mut state = H::new();
        if F::DOMAIN_PURE || phflag != 0 || !context.is_empty() {
            state.update(F::DOMAIN);
            state.update(&[phflag, context.len() as u8]);
            state.update(context);
        }
        state
    }

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
