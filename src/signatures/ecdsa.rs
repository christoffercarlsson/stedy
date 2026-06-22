#![allow(non_snake_case)]
use {
    crate::{
        csprngs::HmacDrbg,
        elliptic_curves::Weierstrass,
        traits::{
            ByteArray, CryptoRng, FieldElement, Hasher, WeierstrassParams, WeierstrassScalar,
        },
        utils::shift_right,
    },
    core::{cmp::Ordering, marker::PhantomData},
};

pub struct Ecdsa<F, H, S, B>
where
    F: FieldElement + WeierstrassParams<F>,
    H: Hasher,
    S: WeierstrassScalar,
    B: ByteArray,
{
    _marker: PhantomData<(F, H, S, B)>,
}

impl<F, H, S, B> Ecdsa<F, H, S, B>
where
    F: FieldElement + WeierstrassParams<F>,
    H: Hasher,
    S: WeierstrassScalar,
    B: ByteArray,
{
    pub fn generate_key_pair(rng: &mut impl CryptoRng) -> (S::Bytes, F::PointBytes) {
        let d = Self::next_scalar(rng);
        let private_key: S::Bytes = d.into();
        let public_key = Self::public_key_from_scalar(&d);
        (private_key, public_key)
    }

    pub fn public_key(private_key: &S::Bytes) -> F::PointBytes {
        let d = S::from(*private_key);
        Self::public_key_from_scalar(&d)
    }

    pub fn sign(private_key: &S::Bytes, message: &[u8]) -> B {
        let d = S::from(*private_key);
        let e = Self::message_representative(message);
        let mut drbg = HmacDrbg::<H>::instantiate(d.into().as_ref(), e.into().as_ref());
        loop {
            let k = Self::next_scalar(&mut drbg);
            if let Some(signature) = Self::try_sign(&k, &d, &e) {
                return signature;
            }
        }
    }

    pub fn verify(message: &[u8], public_key: &F::PointBytes, signature: &B) -> bool {
        let Some((r, s)) = Self::read_signature(signature) else {
            return false;
        };
        let (q, valid_q) = Weierstrass::<F, S>::decompress(public_key);
        if valid_q == 0 {
            return false;
        }
        let e = Self::message_representative(message);
        let w = s.invert();
        let u1 = e * w;
        let u2 = r * w;
        let R = Weierstrass::<F, S>::vartime_double_base(&u2, q, &u1);
        if R.is_identity() {
            return false;
        }
        Self::affine_x_mod_order(&R) == r
    }
}

impl<F, H, S, B> Ecdsa<F, H, S, B>
where
    F: FieldElement + WeierstrassParams<F>,
    H: Hasher,
    S: WeierstrassScalar,
    B: ByteArray,
{
    const DISCARD_BITS: usize = S::Bytes::SIZE * 8 - S::ORDER_BITS;

    fn next_scalar(rng: &mut impl CryptoRng) -> S {
        loop {
            let mut bytes = S::Bytes::new();
            rng.fill(bytes.as_mut());
            let candidate = Self::bits2octets(bytes.as_ref());
            if let Some(scalar) = S::from_canonical(&candidate) {
                return scalar;
            }
        }
    }

    fn public_key_from_scalar(d: &S) -> F::PointBytes {
        (Weierstrass::<F, S>::BASE_POINT * *d).compress()
    }

    fn try_sign(k: &S, d: &S, e: &S) -> Option<B> {
        let point = Weierstrass::<F, S>::BASE_POINT * *k;
        let r = Self::affine_x_mod_order(&point);
        let s = k.invert() * (*e + r * *d);
        let valid = !r.is_zero() & !s.is_zero();
        valid.then(|| Self::create_signature(&r.into(), &s.into()))
    }

    fn create_signature(r_bytes: &S::Bytes, s_bytes: &S::Bytes) -> B {
        let mut signature = B::new();
        let (r, s) =
            Self::signature_from_components_mut(&mut signature).expect("Signature size is correct");
        r.as_mut().copy_from_slice(r_bytes.as_ref());
        s.as_mut().copy_from_slice(s_bytes.as_ref());
        signature
    }

    fn signature_from_components_mut(signature: &mut B) -> Option<(&mut S::Bytes, &mut S::Bytes)> {
        let (r, s) = signature.as_mut().split_at_mut_checked(S::Bytes::SIZE)?;
        let r = S::Bytes::from_slice_mut_checked(r)?;
        let s = S::Bytes::from_slice_mut_checked(s)?;
        Some((r, s))
    }

    fn read_signature(signature: &B) -> Option<(S, S)> {
        let (r, s) = signature.as_ref().split_at(S::Bytes::SIZE);
        let r = S::from_canonical(S::Bytes::from_slice(r))?;
        let s = S::from_canonical(S::Bytes::from_slice(s))?;
        Some((r, s))
    }

    fn affine_x_mod_order(point: &Weierstrass<F, S>) -> S {
        let x = point.affine_x();
        let bytes = *S::Bytes::from_slice(x.as_ref());
        S::from(bytes)
    }

    fn message_representative(message: &[u8]) -> S {
        let digest = H::digest(message);
        let bytes = Self::bits2octets(digest.as_ref());
        S::from(bytes)
    }

    fn bits2octets(bits: &[u8]) -> S::Bytes {
        let size = bits.len();
        let mut bytes = S::Bytes::new();
        match size.cmp(&S::Bytes::SIZE) {
            Ordering::Equal => {
                bytes.as_mut().copy_from_slice(bits);
                shift_right(bytes.as_mut(), Self::DISCARD_BITS);
            }
            Ordering::Less => {
                let offset = S::Bytes::SIZE - size;
                bytes.as_mut()[offset..].copy_from_slice(bits);
            }
            Ordering::Greater => {
                bytes.as_mut().copy_from_slice(&bits[..S::Bytes::SIZE]);
                shift_right(bytes.as_mut(), Self::DISCARD_BITS);
            }
        }
        bytes
    }
}
