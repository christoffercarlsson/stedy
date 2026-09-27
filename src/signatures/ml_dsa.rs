use {
    crate::{
        hashes::{Shake128, Shake256},
        traits::{ByteArray, CryptoRng, MlDsaParams, Xof, XofReader},
        utils::{verify, Choice},
        Secret,
    },
    core::marker::PhantomData,
};

pub type MlDsa44 = MlDsa<4, 4, MlDsa44Params, Shake256, Shake128>;
pub type MlDsa65 = MlDsa<6, 5, MlDsa65Params, Shake256, Shake128>;
pub type MlDsa87 = MlDsa<8, 7, MlDsa87Params, Shake256, Shake128>;

pub struct MlDsa44Params;
pub struct MlDsa65Params;
pub struct MlDsa87Params;

impl MlDsaParams<4, 4> for MlDsa44Params {
    const TAU: usize = 39;
    const LAMBDA: usize = 128;
    const GAMMA1: i32 = 1 << 17;
    const GAMMA2: i32 = (8380417 - 1) / 88;
    const ETA: i32 = 2;
    const BETA: i32 = 78;
    const OMEGA: usize = 80;

    type PrivateKey = Secret<[u8; 2560]>;
    type PublicKey = [u8; 1312];
    type Signature = [u8; 2420];
}

impl MlDsaParams<6, 5> for MlDsa65Params {
    const TAU: usize = 49;
    const LAMBDA: usize = 192;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (8380417 - 1) / 32;
    const ETA: i32 = 4;
    const BETA: i32 = 196;
    const OMEGA: usize = 55;

    type PrivateKey = Secret<[u8; 4032]>;
    type PublicKey = [u8; 1952];
    type Signature = [u8; 3309];
}

impl MlDsaParams<8, 7> for MlDsa87Params {
    const TAU: usize = 60;
    const LAMBDA: usize = 256;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (8380417 - 1) / 32;
    const ETA: i32 = 2;
    const BETA: i32 = 120;
    const OMEGA: usize = 75;

    type PrivateKey = Secret<[u8; 4896]>;
    type PublicKey = [u8; 2592];
    type Signature = [u8; 4627];
}

pub struct MlDsa<const K: usize, const L: usize, P, H, G>
where
    P: MlDsaParams<K, L>,
    H: Xof,
    G: Xof,
{
    _marker: PhantomData<(P, H, G)>,
}

impl<const K: usize, const L: usize, P, H, G> MlDsa<K, L, P, H, G>
where
    P: MlDsaParams<K, L>,
    H: Xof,
    G: Xof,
{
    pub fn generate_key_pair(rng: &mut impl CryptoRng) -> (P::PrivateKey, P::PublicKey) {
        let mut seed = Secret::<[u8; 32]>::new();
        rng.fill(seed.as_mut());
        Self::key_pair(&seed)
    }

    pub fn key_pair(seed: &Secret<[u8; 32]>) -> (P::PrivateKey, P::PublicKey) {
        let mut sk = P::PrivateKey::new();
        let mut pk = P::PublicKey::new();
        Self::key_gen_internal(seed.get(), pk.as_mut(), sk.as_mut());
        (sk, pk)
    }

    pub fn public_key(private_key: &P::PrivateKey) -> P::PublicKey {
        let mut s1 = Secret::from([[0i32; 256]; L]);
        let mut s2 = Secret::from([[0i32; 256]; K]);
        let mut t = Secret::from([[0i32; 256]; K]);
        let (rho, _, _) = Self::sk_decode(
            private_key.as_ref(),
            s1.get_mut(),
            s2.get_mut(),
            t.get_mut(),
        );
        Self::compute_t(rho, s1.get(), s2.get(), t.get_mut());
        let mut t1 = [[0i32; 256]; K];
        for (t1, t) in t1.iter_mut().zip(t.get()) {
            for (t1, &t) in t1.iter_mut().zip(t) {
                *t1 = Self::power2round(t).0;
            }
        }
        let mut pk = P::PublicKey::new();
        Self::pk_encode(rho, &t1, pk.as_mut());
        pk
    }

    pub fn sign(
        private_key: &P::PrivateKey,
        message: &[u8],
        rng: &mut impl CryptoRng,
    ) -> P::Signature {
        let mut rnd = Secret::<[u8; 32]>::new();
        rng.fill(rnd.as_mut());
        let mut signature = P::Signature::new();
        Self::sign_internal(
            private_key.as_ref(),
            &[&[0, 0], message],
            rnd.get(),
            signature.as_mut(),
        );
        signature
    }

    pub fn sign_deterministic(private_key: &P::PrivateKey, message: &[u8]) -> P::Signature {
        let mut signature = P::Signature::new();
        Self::sign_internal(
            private_key.as_ref(),
            &[&[0, 0], message],
            &[0; 32],
            signature.as_mut(),
        );
        signature
    }

    pub fn verify(message: &[u8], public_key: &P::PublicKey, signature: &P::Signature) -> bool {
        Self::verify_internal(public_key.as_ref(), &[&[0, 0], message], signature.as_ref())
    }
}

impl<const K: usize, const L: usize, P, H, G> MlDsa<K, L, P, H, G>
where
    P: MlDsaParams<K, L>,
    H: Xof,
    G: Xof,
{
    const Q: i32 = 8380417;
    const D: usize = 13;
    const R2: i32 = Self::montgomery_form(Self::montgomery_form(1));
    const W1_BOUND: i32 = (Self::Q - 1) / (2 * P::GAMMA2) - 1;
    const ZETAS: [i32; 256] = {
        let mut zetas = [0i32; 256];
        let mut m = 0;
        while m < 256 {
            zetas[m] = Self::zeta_power(Self::bit_rev8(m));
            m += 1;
        }
        zetas
    };

    // Algorithm 6
    fn key_gen_internal(xi: &[u8], pk: &mut [u8], sk: &mut [u8]) {
        let mut seeds = Secret::<[u8; 128]>::new();
        let mut xof = H::new();
        xof.update(xi);
        xof.update(&[K as u8, L as u8]);
        xof.finalize_into(seeds.as_mut());
        let (rho, rest) = seeds.get().split_at(32);
        let (rho_prime, k) = rest.split_at(64);
        let mut s1 = Secret::from([[0i32; 256]; L]);
        let mut s2 = Secret::from([[0i32; 256]; K]);
        Self::expand_s(rho_prime, s1.get_mut(), s2.get_mut());
        let mut t = Secret::from([[0i32; 256]; K]);
        Self::compute_t(rho, s1.get(), s2.get(), t.get_mut());
        let mut t1 = [[0i32; 256]; K];
        for (t1, t) in t1.iter_mut().zip(t.get_mut()) {
            for (t1, t) in t1.iter_mut().zip(t) {
                (*t1, *t) = Self::power2round(*t);
            }
        }
        let t0 = t;
        Self::pk_encode(rho, &t1, pk);
        let mut tr = [0u8; 64];
        H::digest(pk, &mut tr);
        Self::sk_encode(rho, k, &tr, s1.get(), s2.get(), t0.get(), sk);
    }

    // Algorithm 7
    fn sign_internal(sk: &[u8], m_prime: &[&[u8]], rnd: &[u8], signature: &mut [u8]) {
        let mut s1_hat = Secret::from([[0i32; 256]; L]);
        let mut s2_hat = Secret::from([[0i32; 256]; K]);
        let mut t0_hat = Secret::from([[0i32; 256]; K]);
        let (rho, k, tr) =
            Self::sk_decode(sk, s1_hat.get_mut(), s2_hat.get_mut(), t0_hat.get_mut());
        for s in s1_hat.get_mut() {
            Self::ntt(s);
        }
        for s in s2_hat.get_mut() {
            Self::ntt(s);
        }
        for t in t0_hat.get_mut() {
            Self::ntt(t);
        }
        let mut mu = [0u8; 64];
        let mut xof = H::new();
        xof.update(tr);
        for part in m_prime {
            xof.update(part);
        }
        xof.finalize_into(&mut mu);
        let mut rho_double_prime = Secret::<[u8; 64]>::new();
        let mut xof = H::new();
        xof.update(k);
        xof.update(rnd);
        xof.update(&mu);
        xof.finalize_into(rho_double_prime.as_mut());
        let mut a_hat = [[[0i32; 256]; L]; K];
        Self::expand_a(rho, &mut a_hat);
        let mut kappa = 0;
        let mut z = Secret::from([[0i32; 256]; L]);
        let mut w = Secret::from([[0i32; 256]; K]);
        let mut w1 = [0i32; 256];
        let mut w1_bytes = [0u8; 192];
        let w1_size = Self::packed_size(Self::W1_BOUND);
        let mut c_tilde = [0u8; 64];
        let mut h = [[0u8; 256]; K];
        loop {
            Self::expand_mask(rho_double_prime.get(), kappa, z.get_mut());
            kappa += L as u16;
            for y in z.get_mut() {
                Self::ntt(y);
            }
            Self::matrix_vector_ntt(&a_hat, z.get(), w.get_mut());
            let mut xof = H::new();
            xof.update(&mu);
            for w in w.get_mut() {
                Self::inverse_ntt(w);
                for (w1, &w) in w1.iter_mut().zip(w.iter()) {
                    *w1 = Self::high_bits(w);
                }
                Self::simple_bit_pack(&w1, Self::W1_BOUND, &mut w1_bytes[..w1_size]);
                xof.update(&w1_bytes[..w1_size]);
            }
            xof.finalize_into(&mut c_tilde[..P::LAMBDA / 4]);
            let mut c_hat = Self::sample_in_ball(&c_tilde[..P::LAMBDA / 4]);
            Self::ntt(&mut c_hat);
            let mut product = Secret::from([0i32; 256]);
            for (z, s1) in z.get_mut().iter_mut().zip(s1_hat.get()) {
                *product.get_mut() = *s1;
                Self::multiply_ntt(&c_hat, product.get_mut());
                Self::add_ntt(z, product.get());
                Self::inverse_ntt(z);
            }
            for (w, s2) in w.get_mut().iter_mut().zip(s2_hat.get()) {
                *product.get_mut() = *s2;
                Self::multiply_ntt(&c_hat, product.get_mut());
                Self::inverse_ntt(product.get_mut());
                for (w, &cs2) in w.iter_mut().zip(product.get()) {
                    *w = Self::reduce(*w - cs2);
                }
            }
            let z_bound =
                Self::norm_exceeds(z.get().as_flattened().iter().copied(), P::GAMMA1 - P::BETA);
            let r0 = w.get().as_flattened().iter().map(|&w| Self::low_bits(w));
            let r0_bound = Self::norm_exceeds(r0, P::GAMMA2 - P::BETA);
            if z_bound | r0_bound {
                continue;
            }
            let mut ones = 0;
            let mut ct0_bound = false;
            for ((h, t0), w) in h.iter_mut().zip(t0_hat.get()).zip(w.get()) {
                *product.get_mut() = *t0;
                Self::multiply_ntt(&c_hat, product.get_mut());
                Self::inverse_ntt(product.get_mut());
                for ((h, &ct0), &w) in h.iter_mut().zip(product.get()).zip(w) {
                    *h = u8::from(Self::make_hint(-ct0, w + ct0));
                    ones += usize::from(*h);
                }
                ct0_bound |= Self::norm_exceeds(product.get().iter().copied(), P::GAMMA2);
            }
            if !ct0_bound & (ones <= P::OMEGA) {
                break;
            }
        }
        for z in z.get_mut().as_flattened_mut() {
            *z = Self::centered(*z);
        }
        Self::sig_encode(&c_tilde[..P::LAMBDA / 4], z.get(), &h, signature);
    }

    // Algorithm 8
    fn verify_internal(pk: &[u8], m_prime: &[&[u8]], signature: &[u8]) -> bool {
        let mut t1 = [[0i32; 256]; K];
        let rho = Self::pk_decode(pk, &mut t1);
        let mut z = [[0i32; 256]; L];
        let mut h = [[0u8; 256]; K];
        let Some(c_tilde) = Self::sig_decode(signature, &mut z, &mut h) else {
            return false;
        };
        let mut tr = [0u8; 64];
        H::digest(pk, &mut tr);
        let mut mu = [0u8; 64];
        let mut xof = H::new();
        xof.update(&tr);
        for part in m_prime {
            xof.update(part);
        }
        xof.finalize_into(&mut mu);
        let z_bound = Self::norm_exceeds(z.as_flattened().iter().copied(), P::GAMMA1 - P::BETA);
        let mut c_hat = Self::sample_in_ball(c_tilde);
        Self::ntt(&mut c_hat);
        for z in &mut z {
            Self::ntt(z);
        }
        let mut w = [[0i32; 256]; K];
        Self::expand_a_vector_ntt(rho, &z, &mut w);
        for t1 in &mut t1 {
            for x in t1.iter_mut() {
                *x <<= Self::D;
            }
            Self::ntt(t1);
        }
        Self::scalar_vector_ntt(&c_hat, &mut t1);
        for (w, ct1) in w.iter_mut().zip(&t1) {
            for (w, &ct1) in w.iter_mut().zip(ct1) {
                *w = Self::reduce(*w - ct1);
            }
            Self::inverse_ntt(w);
        }
        for (w, h) in w.iter_mut().zip(&h) {
            for (w, &h) in w.iter_mut().zip(h) {
                *w = Self::use_hint(h != 0, *w);
            }
        }
        let w1 = &w;
        let mut w1_bytes = [0u8; 1024];
        let w1_size = K * Self::packed_size(Self::W1_BOUND);
        Self::w1_encode(w1, &mut w1_bytes[..w1_size]);
        let mut c_tilde_prime = [0u8; 64];
        let mut xof = H::new();
        xof.update(&mu);
        xof.update(&w1_bytes[..w1_size]);
        xof.finalize_into(&mut c_tilde_prime[..P::LAMBDA / 4]);
        !z_bound & verify(c_tilde, &c_tilde_prime[..P::LAMBDA / 4])
    }

    // Algorithm 14
    fn coeff_from_three_bytes(b0: u8, b1: u8, b2: u8) -> Option<i32> {
        let z = 65536 * i32::from(b2 % 128) + 256 * i32::from(b1) + i32::from(b0);
        (z < Self::Q).then_some(z)
    }

    // Algorithm 15
    fn coeff_from_half_byte(b: u8) -> Option<i32> {
        match (P::ETA, b) {
            (2, 0..=14) => Some(2 - i32::from(b % 5)),
            (4, 0..=8) => Some(4 - i32::from(b)),
            _ => None,
        }
    }

    // Algorithm 16
    fn simple_bit_pack(w: &[i32; 256], b: i32, bytes: &mut [u8]) {
        let c = Self::bitlen(b);
        let group = 8 / Self::gcd(c, 8);
        for (w, chunk) in w
            .chunks_exact(group)
            .zip(bytes.chunks_exact_mut(group * c / 8))
        {
            let packed = w
                .iter()
                .enumerate()
                .fold(0u128, |packed, (i, &x)| packed | ((x as u128) << (i * c)));
            chunk.copy_from_slice(&packed.to_le_bytes()[..chunk.len()]);
        }
    }

    // Algorithm 17
    fn bit_pack(w: &[i32; 256], a: i32, b: i32, bytes: &mut [u8]) {
        let mut v = Secret::from([0i32; 256]);
        for (v, w) in v.get_mut().iter_mut().zip(w) {
            *v = b - w;
        }
        Self::simple_bit_pack(v.get(), a + b, bytes);
    }

    // Algorithm 18
    fn simple_bit_unpack(bytes: &[u8], b: i32, w: &mut [i32; 256]) {
        let c = Self::bitlen(b);
        let group = 8 / Self::gcd(c, 8);
        let mask = (1u128 << c) - 1;
        for (w, chunk) in w
            .chunks_exact_mut(group)
            .zip(bytes.chunks_exact(group * c / 8))
        {
            let mut packed = [0u8; 16];
            packed[..chunk.len()].copy_from_slice(chunk);
            let packed = u128::from_le_bytes(packed);
            for (i, x) in w.iter_mut().enumerate() {
                *x = ((packed >> (i * c)) & mask) as i32;
            }
        }
    }

    // Algorithm 19
    fn bit_unpack(bytes: &[u8], a: i32, b: i32, w: &mut [i32; 256]) {
        Self::simple_bit_unpack(bytes, a + b, w);
        for x in w.iter_mut() {
            *x = b - *x;
        }
    }

    // Algorithm 20
    fn hint_bit_pack(h: &[[u8; 256]; K], bytes: &mut [u8]) {
        bytes.fill(0);
        let mut index = 0;
        for (i, h) in h.iter().enumerate() {
            for (j, &bit) in h.iter().enumerate() {
                if bit != 0 {
                    bytes[index] = j as u8;
                    index += 1;
                }
            }
            bytes[P::OMEGA + i] = index as u8;
        }
    }

    // Algorithm 21
    fn hint_bit_unpack(bytes: &[u8], h: &mut [[u8; 256]; K]) -> bool {
        *h = [[0; 256]; K];
        let mut index = 0;
        for (i, h) in h.iter_mut().enumerate() {
            let end = usize::from(bytes[P::OMEGA + i]);
            if end < index || end > P::OMEGA {
                return false;
            }
            let first = index;
            while index < end {
                if index > first && bytes[index - 1] >= bytes[index] {
                    return false;
                }
                h[usize::from(bytes[index])] = 1;
                index += 1;
            }
        }
        bytes[index..P::OMEGA].iter().all(|&y| y == 0)
    }

    // Algorithm 22
    fn pk_encode(rho: &[u8], t1: &[[i32; 256]; K], pk: &mut [u8]) {
        let (rho_bytes, t1_bytes) = pk.split_at_mut(32);
        let (t1_bytes, _) = t1_bytes.as_chunks_mut::<320>();
        rho_bytes.copy_from_slice(rho);
        for (t, bytes) in t1.iter().zip(t1_bytes) {
            Self::simple_bit_pack(t, 1023, bytes);
        }
    }

    // Algorithm 23
    fn pk_decode<'a>(pk: &'a [u8], t1: &mut [[i32; 256]; K]) -> &'a [u8] {
        let (rho, t1_bytes) = pk.split_at(32);
        let (t1_bytes, _) = t1_bytes.as_chunks::<320>();
        for (t, bytes) in t1.iter_mut().zip(t1_bytes) {
            Self::simple_bit_unpack(bytes, 1023, t);
        }
        rho
    }

    // Algorithm 24
    fn sk_encode(
        rho: &[u8],
        k: &[u8],
        tr: &[u8],
        s1: &[[i32; 256]; L],
        s2: &[[i32; 256]; K],
        t0: &[[i32; 256]; K],
        sk: &mut [u8],
    ) {
        let s_size = Self::packed_size(2 * P::ETA);
        let (rho_bytes, rest) = sk.split_at_mut(32);
        let (k_bytes, rest) = rest.split_at_mut(32);
        let (tr_bytes, rest) = rest.split_at_mut(64);
        let (s1_bytes, rest) = rest.split_at_mut(L * s_size);
        let (s2_bytes, t0_bytes) = rest.split_at_mut(K * s_size);
        rho_bytes.copy_from_slice(rho);
        k_bytes.copy_from_slice(k);
        tr_bytes.copy_from_slice(tr);
        for (s, bytes) in s1.iter().zip(s1_bytes.chunks_exact_mut(s_size)) {
            Self::bit_pack(s, P::ETA, P::ETA, bytes);
        }
        for (s, bytes) in s2.iter().zip(s2_bytes.chunks_exact_mut(s_size)) {
            Self::bit_pack(s, P::ETA, P::ETA, bytes);
        }
        let t0_size = Self::packed_size((1 << Self::D) - 1);
        for (t, bytes) in t0.iter().zip(t0_bytes.chunks_exact_mut(t0_size)) {
            Self::bit_pack(t, (1 << (Self::D - 1)) - 1, 1 << (Self::D - 1), bytes);
        }
    }

    // Algorithm 25
    fn sk_decode<'a>(
        sk: &'a [u8],
        s1: &mut [[i32; 256]; L],
        s2: &mut [[i32; 256]; K],
        t0: &mut [[i32; 256]; K],
    ) -> (&'a [u8], &'a [u8], &'a [u8]) {
        let s_size = Self::packed_size(2 * P::ETA);
        let (rho, rest) = sk.split_at(32);
        let (k, rest) = rest.split_at(32);
        let (tr, rest) = rest.split_at(64);
        let (s1_bytes, rest) = rest.split_at(L * s_size);
        let (s2_bytes, t0_bytes) = rest.split_at(K * s_size);
        for (s, bytes) in s1.iter_mut().zip(s1_bytes.chunks_exact(s_size)) {
            Self::bit_unpack(bytes, P::ETA, P::ETA, s);
        }
        for (s, bytes) in s2.iter_mut().zip(s2_bytes.chunks_exact(s_size)) {
            Self::bit_unpack(bytes, P::ETA, P::ETA, s);
        }
        let t0_size = Self::packed_size((1 << Self::D) - 1);
        for (t, bytes) in t0.iter_mut().zip(t0_bytes.chunks_exact(t0_size)) {
            Self::bit_unpack(bytes, (1 << (Self::D - 1)) - 1, 1 << (Self::D - 1), t);
        }
        (rho, k, tr)
    }

    // Algorithm 26
    fn sig_encode(c_tilde: &[u8], z: &[[i32; 256]; L], h: &[[u8; 256]; K], signature: &mut [u8]) {
        let z_size = Self::packed_size(2 * P::GAMMA1 - 1);
        let (c_bytes, rest) = signature.split_at_mut(P::LAMBDA / 4);
        let (z_bytes, h_bytes) = rest.split_at_mut(L * z_size);
        c_bytes.copy_from_slice(c_tilde);
        for (z, bytes) in z.iter().zip(z_bytes.chunks_exact_mut(z_size)) {
            Self::bit_pack(z, P::GAMMA1 - 1, P::GAMMA1, bytes);
        }
        Self::hint_bit_pack(h, h_bytes);
    }

    // Algorithm 27
    fn sig_decode<'a>(
        signature: &'a [u8],
        z: &mut [[i32; 256]; L],
        h: &mut [[u8; 256]; K],
    ) -> Option<&'a [u8]> {
        let z_size = Self::packed_size(2 * P::GAMMA1 - 1);
        let (c_tilde, rest) = signature.split_at(P::LAMBDA / 4);
        let (z_bytes, h_bytes) = rest.split_at(L * z_size);
        for (z, bytes) in z.iter_mut().zip(z_bytes.chunks_exact(z_size)) {
            Self::bit_unpack(bytes, P::GAMMA1 - 1, P::GAMMA1, z);
        }
        Self::hint_bit_unpack(h_bytes, h).then_some(c_tilde)
    }

    // Algorithm 28
    fn w1_encode(w1: &[[i32; 256]; K], bytes: &mut [u8]) {
        let size = Self::packed_size(Self::W1_BOUND);
        for (w, bytes) in w1.iter().zip(bytes.chunks_exact_mut(size)) {
            Self::simple_bit_pack(w, Self::W1_BOUND, bytes);
        }
    }

    // Algorithm 29
    fn sample_in_ball(rho: &[u8]) -> [i32; 256] {
        let mut c = [0i32; 256];
        let mut xof = H::new();
        xof.update(rho);
        let mut reader = xof.finalize_xof();
        let mut s = [0u8; 8];
        reader.read(&mut s);
        let h = u64::from_le_bytes(s);
        for i in 256 - P::TAU..256 {
            let mut j = [0u8; 1];
            reader.read(&mut j);
            while usize::from(j[0]) > i {
                reader.read(&mut j);
            }
            let j = usize::from(j[0]);
            c[i] = c[j];
            c[j] = 1 - 2 * ((h >> (i + P::TAU - 256)) & 1) as i32;
        }
        c
    }

    // Algorithm 30
    fn rej_ntt_poly(rho: &[u8], s: u8, r: u8) -> [i32; 256] {
        let mut xof = G::new();
        xof.update(rho);
        xof.update(&[s, r]);
        let mut reader = xof.finalize_xof();
        let mut a = [0i32; 256];
        let mut j = 0;
        while j < 256 {
            let mut block = [[0u8; 3]; 56];
            reader.read(block.as_flattened_mut());
            let coefficients = block
                .iter()
                .filter_map(|&[b0, b1, b2]| Self::coeff_from_three_bytes(b0, b1, b2));
            for z in coefficients {
                if j < 256 {
                    a[j] = z;
                    j += 1;
                }
            }
        }
        a
    }

    // Algorithm 31
    fn rej_bounded_poly(rho: &[u8], r: u16, a: &mut [i32; 256]) {
        let mut xof = H::new();
        xof.update(rho);
        xof.update(&r.to_le_bytes());
        let mut reader = xof.finalize_xof();
        let mut j = 0;
        while j < 256 {
            let mut block = Secret::<[u8; 136]>::new();
            reader.read(block.as_mut());
            let coefficients = block
                .get()
                .iter()
                .flat_map(|&z| {
                    [
                        Self::coeff_from_half_byte(z % 16),
                        Self::coeff_from_half_byte(z / 16),
                    ]
                })
                .flatten();
            for z in coefficients {
                if j < 256 {
                    a[j] = z;
                    j += 1;
                }
            }
        }
    }

    fn compute_t(rho: &[u8], s1: &[[i32; 256]; L], s2: &[[i32; 256]; K], t: &mut [[i32; 256]; K]) {
        let mut s1_hat = Secret::from(*s1);
        for s in s1_hat.get_mut() {
            Self::ntt(s);
        }
        Self::expand_a_vector_ntt(rho, s1_hat.get(), t);
        for t in t.iter_mut() {
            Self::inverse_ntt(t);
        }
        Self::add_vector_ntt(t, s2);
    }

    // Algorithm 32
    fn expand_a(rho: &[u8], a_hat: &mut [[[i32; 256]; L]; K]) {
        for (r, row) in a_hat.iter_mut().enumerate() {
            for (s, a) in row.iter_mut().enumerate() {
                *a = Self::rej_ntt_poly(rho, s as u8, r as u8);
            }
        }
    }

    // Algorithm 33
    fn expand_s(rho: &[u8], s1: &mut [[i32; 256]; L], s2: &mut [[i32; 256]; K]) {
        for (r, s) in s1.iter_mut().enumerate() {
            Self::rej_bounded_poly(rho, r as u16, s);
        }
        for (r, s) in s2.iter_mut().enumerate() {
            Self::rej_bounded_poly(rho, (L + r) as u16, s);
        }
    }

    // Algorithm 34
    fn expand_mask(rho: &[u8], mu: u16, y: &mut [[i32; 256]; L]) {
        let c = 1 + Self::bitlen(P::GAMMA1 - 1);
        let mut v = Secret::<[u8; 640]>::new();
        for (r, y) in y.iter_mut().enumerate() {
            let mut xof = H::new();
            xof.update(rho);
            xof.update(&(mu + r as u16).to_le_bytes());
            xof.finalize_into(&mut v.as_mut()[..32 * c]);
            Self::bit_unpack(&v.as_ref()[..32 * c], P::GAMMA1 - 1, P::GAMMA1, y);
        }
    }

    // Algorithm 35
    fn power2round(r: i32) -> (i32, i32) {
        let r = Self::mod_q(r);
        let mut r0 = r % (1 << Self::D);
        r0 -= (((1 << (Self::D - 1)) - r0) >> 31) & (1 << Self::D);
        ((r - r0) >> Self::D, r0)
    }

    // Algorithm 36
    fn decompose(r: i32) -> (i32, i32) {
        let r = Self::mod_q(r);
        let mut r0 = r % (2 * P::GAMMA2);
        r0 -= ((P::GAMMA2 - r0) >> 31) & (2 * P::GAMMA2);
        let corner = Self::zero_mask(r - r0 - (Self::Q - 1));
        let r1 = ((r - r0) / (2 * P::GAMMA2)) & !corner;
        (r1, r0 + corner)
    }

    // Algorithm 37
    fn high_bits(r: i32) -> i32 {
        Self::decompose(r).0
    }

    // Algorithm 38
    fn low_bits(r: i32) -> i32 {
        Self::decompose(r).1
    }

    // Algorithm 39
    fn make_hint(z: i32, r: i32) -> bool {
        Self::high_bits(r) != Self::high_bits(r + z)
    }

    // Algorithm 40
    fn use_hint(h: bool, r: i32) -> i32 {
        let m = (Self::Q - 1) / (2 * P::GAMMA2);
        let (r1, r0) = Self::decompose(r);
        match (h, r0 > 0) {
            (true, true) => (r1 + 1) % m,
            (true, false) => (r1 - 1).rem_euclid(m),
            (false, _) => r1,
        }
    }

    // Algorithm 41
    fn ntt(w: &mut [i32; 256]) {
        Self::ntt_layer::<128>(w, &Self::ZETAS[1..2]);
        Self::ntt_layer::<64>(w, &Self::ZETAS[2..4]);
        Self::ntt_layer::<32>(w, &Self::ZETAS[4..8]);
        Self::ntt_layer::<16>(w, &Self::ZETAS[8..16]);
        Self::ntt_layer::<8>(w, &Self::ZETAS[16..32]);
        Self::ntt_layer::<4>(w, &Self::ZETAS[32..64]);
        Self::ntt_layer::<2>(w, &Self::ZETAS[64..128]);
        Self::ntt_layer::<1>(w, &Self::ZETAS[128..256]);
    }

    fn ntt_layer<const LEN: usize>(w: &mut [i32; 256], zetas: &[i32]) {
        let (halves, _) = w.as_chunks_mut::<LEN>();
        let (blocks, _) = halves.as_chunks_mut::<2>();
        for ([lower, upper], &zeta) in blocks.iter_mut().zip(zetas) {
            for (a, b) in lower.iter_mut().zip(upper.iter_mut()) {
                let t = Self::montgomery_multiply(zeta, *b);
                *b = *a - t;
                *a += t;
            }
        }
    }

    // Algorithm 42
    fn inverse_ntt(w: &mut [i32; 256]) {
        Self::inverse_ntt_layer::<1>(w, &Self::ZETAS[128..256]);
        Self::inverse_ntt_layer::<2>(w, &Self::ZETAS[64..128]);
        Self::inverse_ntt_layer::<4>(w, &Self::ZETAS[32..64]);
        Self::inverse_ntt_layer::<8>(w, &Self::ZETAS[16..32]);
        Self::inverse_ntt_layer::<16>(w, &Self::ZETAS[8..16]);
        Self::inverse_ntt_layer::<32>(w, &Self::ZETAS[4..8]);
        Self::inverse_ntt_layer::<64>(w, &Self::ZETAS[2..4]);
        Self::inverse_ntt_layer::<128>(w, &Self::ZETAS[1..2]);
        let f = Self::montgomery_form(8347681);
        for a in w.iter_mut() {
            *a = Self::montgomery_multiply(*a, f);
        }
    }

    fn inverse_ntt_layer<const LEN: usize>(w: &mut [i32; 256], zetas: &[i32]) {
        let (halves, _) = w.as_chunks_mut::<LEN>();
        let (blocks, _) = halves.as_chunks_mut::<2>();
        for ([lower, upper], &zeta) in blocks.iter_mut().zip(zetas.iter().rev()) {
            for (a, b) in lower.iter_mut().zip(upper.iter_mut()) {
                let t = *a;
                *a = t + *b;
                *b = Self::montgomery_multiply(-zeta, t - *b);
            }
        }
    }

    // Algorithm 43
    const fn bit_rev8(m: usize) -> usize {
        (m as u8).reverse_bits() as usize
    }

    // Algorithm 44
    fn add_ntt(a: &mut [i32; 256], b: &[i32; 256]) {
        for (a, b) in a.iter_mut().zip(b) {
            *a = Self::reduce(*a + b);
        }
    }

    // Algorithm 45
    fn multiply_ntt(a: &[i32; 256], b: &mut [i32; 256]) {
        for (a, b) in a.iter().zip(b.iter_mut()) {
            *b = Self::montgomery_multiply(Self::montgomery_multiply(*a, *b), Self::R2);
        }
    }

    // Algorithm 46
    fn add_vector_ntt<const N: usize>(v: &mut [[i32; 256]; N], w: &[[i32; 256]; N]) {
        for (v, w) in v.iter_mut().zip(w) {
            Self::add_ntt(v, w);
        }
    }

    // Algorithm 47
    fn scalar_vector_ntt<const N: usize>(c: &[i32; 256], v: &mut [[i32; 256]; N]) {
        for v in v {
            Self::multiply_ntt(c, v);
        }
    }

    // Algorithm 48
    fn matrix_vector_ntt(
        a_hat: &[[[i32; 256]; L]; K],
        v: &[[i32; 256]; L],
        w: &mut [[i32; 256]; K],
    ) {
        for (row, w) in a_hat.iter().zip(w) {
            *w = [0; 256];
            for (a, v) in row.iter().zip(v) {
                Self::add_multiply_ntt(w, a, v);
            }
            Self::multiply_by_r(w);
        }
    }

    fn expand_a_vector_ntt(rho: &[u8], v: &[[i32; 256]; L], w: &mut [[i32; 256]; K]) {
        for (r, w) in w.iter_mut().enumerate() {
            *w = [0; 256];
            for (s, v) in v.iter().enumerate() {
                let a = Self::rej_ntt_poly(rho, s as u8, r as u8);
                Self::add_multiply_ntt(w, &a, v);
            }
            Self::multiply_by_r(w);
        }
    }

    fn add_multiply_ntt(w: &mut [i32; 256], a: &[i32; 256], v: &[i32; 256]) {
        for ((w, a), v) in w.iter_mut().zip(a).zip(v) {
            *w += Self::montgomery_multiply(*a, *v);
        }
    }

    fn multiply_by_r(w: &mut [i32; 256]) {
        for w in w.iter_mut() {
            *w = Self::montgomery_multiply(*w, Self::R2);
        }
    }

    // Algorithm 49
    const fn montgomery_reduce(a: i64) -> i32 {
        let t = (a as i32).wrapping_mul(58728449);
        ((a - t as i64 * Self::Q as i64) >> 32) as i32
    }

    const fn montgomery_multiply(a: i32, b: i32) -> i32 {
        Self::montgomery_reduce(a as i64 * b as i64)
    }

    const fn bitlen(b: i32) -> usize {
        (32 - b.leading_zeros()) as usize
    }

    const fn packed_size(b: i32) -> usize {
        32 * Self::bitlen(b)
    }

    const fn gcd(a: usize, b: usize) -> usize {
        if b == 0 {
            a
        } else {
            Self::gcd(b, a % b)
        }
    }

    const fn reduce(a: i32) -> i32 {
        a - ((a + (1 << 22)) >> 23) * Self::Q
    }

    const fn mod_q(a: i32) -> i32 {
        let a = Self::reduce(a);
        a + ((a >> 31) & Self::Q)
    }

    const fn zero_mask(a: i32) -> i32 {
        !((a | a.wrapping_neg()) >> 31)
    }

    const fn centered(a: i32) -> i32 {
        let a = Self::mod_q(a);
        a - ((((Self::Q - 1) / 2 - a) >> 31) & Self::Q)
    }

    fn norm_exceeds(values: impl Iterator<Item = i32>, bound: i32) -> bool {
        Choice::nonzero(values.fold(0, |violation, x| {
            let x = Self::centered(x);
            let mask = x >> 31;
            let magnitude = (x ^ mask) - mask;
            violation | ((bound - 1 - magnitude) >> 31)
        }))
        .to_bool()
    }

    const fn montgomery_form(a: i32) -> i32 {
        ((a as u64 * (1 << 32)) % Self::Q as u64) as i32
    }

    const fn zeta_power(exponent: usize) -> i32 {
        let mut power = Self::montgomery_form(1);
        let mut k = 0;
        while k < exponent {
            power = Self::montgomery_multiply(power, Self::montgomery_form(1753));
            k += 1;
        }
        power
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{csprngs::Rng, hashes::Sha3_256},
        hex_literal::hex,
    };

    const MESSAGE: &[u8] = b"example";

    #[test]
    fn test_ml_dsa_44() {
        let mut rng = Rng::from(&[0u8; 128]);
        let (private_key, public_key) = MlDsa44::generate_key_pair(&mut rng);
        assert_eq!(
            Sha3_256::digest(private_key.as_ref()),
            hex!("57587d08af13d92b1231c55a102c967268976d438674646a9f190bc5828918c7")
        );
        assert_eq!(
            Sha3_256::digest(&public_key),
            hex!("c0e23d7a0883c28e6bd1b6275d5f08c185f68d1dd6d7e2fe121c1df64b129eb4")
        );
        assert_eq!(MlDsa44::public_key(&private_key), public_key);
        let signature = MlDsa44::sign(&private_key, MESSAGE, &mut rng);
        assert_eq!(
            Sha3_256::digest(&signature),
            hex!("971579d41bc5f5b64c78e90f157f378ad7df272e057f201039e882a2d8bcfbda")
        );
        assert!(MlDsa44::verify(MESSAGE, &public_key, &signature));
        let signature = MlDsa44::sign_deterministic(&private_key, MESSAGE);
        assert_eq!(
            Sha3_256::digest(&signature),
            hex!("981d53044f786d70725a5c60de3de3b2892b2841648427d69616095dcb2d4cf9")
        );
        assert!(MlDsa44::verify(MESSAGE, &public_key, &signature));
    }

    #[test]
    fn test_ml_dsa_65() {
        let mut rng = Rng::from(&[0u8; 128]);
        let (private_key, public_key) = MlDsa65::generate_key_pair(&mut rng);
        assert_eq!(
            Sha3_256::digest(private_key.as_ref()),
            hex!("c9e018a211d56f87535da4d6ea5790c49e444acf5e845fe3cb1fcccb0b8aafe8")
        );
        assert_eq!(
            Sha3_256::digest(&public_key),
            hex!("a816046ec8eef97e771a95f383649c3b1ca01060724e8d235e2ba7b2c0821678")
        );
        assert_eq!(MlDsa65::public_key(&private_key), public_key);
        let signature = MlDsa65::sign(&private_key, MESSAGE, &mut rng);
        assert_eq!(
            Sha3_256::digest(&signature),
            hex!("40c13b3c43438c975c2a8b5ea1de90eac1a2936c1ce032ec660e9b103c7be919")
        );
        assert!(MlDsa65::verify(MESSAGE, &public_key, &signature));
        let signature = MlDsa65::sign_deterministic(&private_key, MESSAGE);
        assert_eq!(
            Sha3_256::digest(&signature),
            hex!("ed7dd3c5cd4c6e15e0202c3cfa9bebd8273d2853fd6aa712de83fff668fa7de3")
        );
        assert!(MlDsa65::verify(MESSAGE, &public_key, &signature));
    }

    #[test]
    fn test_ml_dsa_87() {
        let mut rng = Rng::from(&[0u8; 128]);
        let (private_key, public_key) = MlDsa87::generate_key_pair(&mut rng);
        assert_eq!(
            Sha3_256::digest(private_key.as_ref()),
            hex!("90969e4b5946d357743b1b0900bee5c8913bb1db71ec041b2b10c8ef5abdb982")
        );
        assert_eq!(
            Sha3_256::digest(&public_key),
            hex!("baa977e5732d13de8f5a0e16667667465af77949dbb5faf8c242ddb4e1a29a7c")
        );
        assert_eq!(MlDsa87::public_key(&private_key), public_key);
        let signature = MlDsa87::sign(&private_key, MESSAGE, &mut rng);
        assert_eq!(
            Sha3_256::digest(&signature),
            hex!("f3198af2e7b38e3a90774f15748ca2820800f6035206074dfdc00e84bedba475")
        );
        assert!(MlDsa87::verify(MESSAGE, &public_key, &signature));
        let signature = MlDsa87::sign_deterministic(&private_key, MESSAGE);
        assert_eq!(
            Sha3_256::digest(&signature),
            hex!("5e68d93732e191d31530592bfa7ee30bff0d22c7331bf6781378ae2f72222388")
        );
        assert!(MlDsa87::verify(MESSAGE, &public_key, &signature));
    }
}
