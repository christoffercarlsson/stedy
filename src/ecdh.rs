use {
    crate::traits::{CryptoRng, FieldElement},
    core::marker::PhantomData,
};

pub struct Ecdh<F: FieldElement<Bytes = [u8; 32]>> {
    _f: PhantomData<F>,
}

impl<F: FieldElement<Bytes = [u8; 32]>> Ecdh<F> {
    pub fn generate_key_pair<R: CryptoRng>(rng: &mut R) -> ([u8; 32], [u8; 32]) {
        let mut private_key = [0u8; 32];
        rng.fill(&mut private_key);
        let public_key = Self::get_public_key(&private_key);
        (private_key, public_key)
    }

    pub fn get_public_key(private_key: &[u8; 32]) -> [u8; 32] {
        let base_point = F::from(9);
        Self::scalar_mult(private_key, base_point).into()
    }

    pub fn key_exchange(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
        let public = F::from(*public_key);
        Self::scalar_mult(private_key, public).into()
    }
}

impl<F: FieldElement<Bytes = [u8; 32]>> Ecdh<F> {
    fn scalar_mult(k: &[u8; 32], u: F) -> F {
        let mut scalar = *k;
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        let x1 = u;
        let mut x2 = F::ONE;
        let mut z2 = F::ZERO;
        let mut x3 = u;
        let mut z3 = F::ONE;
        let mut swap = 0u64;
        for i in (0..255).rev() {
            let byte_index = i / 8;
            let bit_index = i % 8;
            let bit = ((scalar[byte_index] >> bit_index) & 1) as u64;
            swap ^= bit;
            F::swap(&mut x2, &mut x3, swap);
            F::swap(&mut z2, &mut z3, swap);
            swap = bit;
            let a = x2 + z2;
            let aa = a.square();
            let b = x2 - z2;
            let bb = b.square();
            let e = aa - bb;
            let c = x3 + z3;
            let d = x3 - z3;
            let da = d * a;
            let cb = c * b;
            x3 = (da + cb).square();
            z3 = x1 * (da - cb).square();
            x2 = aa * bb;
            let a24 = F::from(121665);
            z2 = e * (aa + a24 * e);
        }
        F::swap(&mut x2, &mut x3, swap);
        F::swap(&mut z2, &mut z3, swap);
        x2 / z2
    }
}
