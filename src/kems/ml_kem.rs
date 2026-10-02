use {
    crate::{
        hashes::{Sha3_256, Sha3_512, Shake128, Shake256},
        traits::{ByteArray, CryptoRng, Hasher, MlKemParams, Xof, XofReader},
        utils::{verify, Choice, Secret},
    },
    core::marker::PhantomData,
};

pub type MlKem512 = MlKem<2, MlKem512Params, Sha3_512, Sha3_256, Shake128, Shake256>;
pub type MlKem768 = MlKem<3, MlKem768Params, Sha3_512, Sha3_256, Shake128, Shake256>;
pub type MlKem1024 = MlKem<4, MlKem1024Params, Sha3_512, Sha3_256, Shake128, Shake256>;

pub struct MlKem512Params;
pub struct MlKem768Params;
pub struct MlKem1024Params;

impl MlKemParams<2> for MlKem512Params {
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;

    type Seed = [u8; 64];
    type SharedSecret = [u8; 32];
    type PrivateKey = [u8; 1632];
    type PublicKey = [u8; 800];
    type Ciphertext = [u8; 768];
}

impl MlKemParams<3> for MlKem768Params {
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;

    type Seed = [u8; 64];
    type SharedSecret = [u8; 32];
    type PrivateKey = [u8; 2400];
    type PublicKey = [u8; 1184];
    type Ciphertext = [u8; 1088];
}

impl MlKemParams<4> for MlKem1024Params {
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;

    type Seed = [u8; 64];
    type SharedSecret = [u8; 32];
    type PrivateKey = [u8; 3168];
    type PublicKey = [u8; 1568];
    type Ciphertext = [u8; 1568];
}

pub struct MlKem<const K: usize, P, G, H, X, F>
where
    P: MlKemParams<K>,
    G: Hasher<Output = [u8; 64]>,
    H: Hasher<Output = [u8; 32]>,
    X: Xof,
    F: Xof,
{
    _marker: PhantomData<(P, G, H, X, F)>,
}

impl<const K: usize, P, G, H, X, F> MlKem<K, P, G, H, X, F>
where
    P: MlKemParams<K>,
    G: Hasher<Output = [u8; 64]>,
    H: Hasher<Output = [u8; 32]>,
    X: Xof,
    F: Xof,
{
    pub fn generate_key_pair(rng: &mut impl CryptoRng) -> (P::PrivateKey, P::PublicKey) {
        let mut seed = Secret::from(P::Seed::new());
        rng.fill(seed.get_mut().as_mut());
        Self::key_pair(seed.get())
    }

    pub fn key_pair(seed: &P::Seed) -> (P::PrivateKey, P::PublicKey) {
        let (d, z) = seed.as_ref().split_at(32);
        let mut keys = (P::PrivateKey::new(), P::PublicKey::new());
        let (dk, ek) = &mut keys;
        Self::key_gen_internal(d, z, ek.as_mut(), dk.as_mut());
        keys
    }

    pub fn public_key(private_key: &P::PrivateKey) -> P::PublicKey {
        let (_, rest) = private_key.as_ref().split_at(384 * K);
        let (ek, _) = rest.split_at(384 * K + 32);
        P::PublicKey::from_slice(ek)
    }

    pub fn encapsulate(
        public_key: &P::PublicKey,
        rng: &mut impl CryptoRng,
    ) -> Option<(P::SharedSecret, P::Ciphertext)> {
        Self::encapsulation_key_check(public_key.as_ref()).then(|| {
            let mut m = Secret::from([0u8; 32]);
            rng.fill(m.as_mut());
            let (k, c) = Self::encaps_internal(public_key.as_ref(), m.as_ref());
            (P::SharedSecret::from_slice(k.get()), c)
        })
    }

    pub fn decapsulate(
        private_key: &P::PrivateKey,
        ciphertext: &P::Ciphertext,
    ) -> Option<P::SharedSecret> {
        Self::decapsulation_key_check(private_key.as_ref()).then(|| {
            let k = Self::decaps_internal(private_key.as_ref(), ciphertext.as_ref());
            P::SharedSecret::from_slice(k.get())
        })
    }
}

impl<const K: usize, P, G, H, X, F> MlKem<K, P, G, H, X, F>
where
    P: MlKemParams<K>,
    G: Hasher<Output = [u8; 64]>,
    H: Hasher<Output = [u8; 32]>,
    X: Xof,
    F: Xof,
{
    const Q: i16 = 3329;
    const ZETAS: [i16; 128] = {
        let mut zetas = [0i16; 128];
        let mut i = 0;
        while i < 128 {
            zetas[i] = Self::zeta_power(Self::bit_rev7(i));
            i += 1;
        }
        zetas
    };
    const GAMMAS: [i16; 128] = {
        let mut gammas = [0i16; 128];
        let mut i = 0;
        while i < 128 {
            gammas[i] = Self::zeta_power(2 * Self::bit_rev7(i) + 1);
            i += 1;
        }
        gammas
    };

    // Algorithm 5
    fn byte_encode(d: usize, f: &[i16; 256], bytes: &mut [u8]) {
        let (groups, _) = f.as_chunks::<8>();
        for (group, chunk) in groups.iter().zip(bytes.chunks_exact_mut(d)) {
            let packed = group.iter().enumerate().fold(0u128, |packed, (i, &a)| {
                packed | ((Self::reduce(a) as u128) << (i * d))
            });
            chunk.copy_from_slice(&packed.to_le_bytes()[..d]);
        }
    }

    // Algorithm 6
    fn byte_decode(d: usize, bytes: &[u8], f: &mut [i16; 256]) {
        let mask = (1u128 << d) - 1;
        let (groups, _) = f.as_chunks_mut::<8>();
        for (group, chunk) in groups.iter_mut().zip(bytes.chunks_exact(d)) {
            let mut packed = [0u8; 16];
            packed[..d].copy_from_slice(chunk);
            let packed = u128::from_le_bytes(packed);
            for (i, a) in group.iter_mut().enumerate() {
                let x = ((packed >> (i * d)) & mask) as i16;
                *a = if d < 12 { x } else { x % Self::Q };
            }
        }
    }

    fn compress(d: usize, x: i16) -> i16 {
        let x = Self::reduce(x) as u32;
        (((x << d) + Self::Q as u32 / 2) / Self::Q as u32 % (1 << d)) as i16
    }

    fn decompress(d: usize, y: i16) -> i16 {
        ((Self::Q as u32 * y as u32 + (1 << (d - 1))) >> d) as i16
    }

    // Algorithm 7
    fn sample_ntt(rho: &[u8], j: u8, i: u8) -> [i16; 256] {
        let mut xof = X::new();
        xof.update(rho);
        xof.update(&[j, i]);
        let mut reader = xof.finalize_xof();
        let mut a = [0i16; 256];
        let mut j = 0;
        while j < 256 {
            let mut block = [[0u8; 3]; 56];
            reader.read(block.as_flattened_mut());
            for c in block {
                let d1 = i16::from(c[0]) + 256 * i16::from(c[1] % 16);
                let d2 = i16::from(c[1] / 16) + 16 * i16::from(c[2]);
                if d1 < Self::Q && j < 256 {
                    a[j] = d1;
                    j += 1;
                }
                if d2 < Self::Q && j < 256 {
                    a[j] = d2;
                    j += 1;
                }
            }
        }
        a
    }

    // Algorithm 8
    fn sample_poly_cbd(eta: usize, bytes: &[u8], f: &mut [i16; 256]) {
        Self::byte_decode(2 * eta, &bytes[..64 * eta], f);
        let mask = (1 << eta) - 1;
        for a in f.iter_mut() {
            let x = (*a & mask).count_ones() as i16;
            let y = ((*a >> eta) & mask).count_ones() as i16;
            *a = x - y;
        }
    }

    // Algorithm 9
    fn ntt(f: &mut [i16; 256]) {
        Self::ntt_layer::<128>(f, &Self::ZETAS[1..2]);
        Self::ntt_layer::<64>(f, &Self::ZETAS[2..4]);
        Self::ntt_layer::<32>(f, &Self::ZETAS[4..8]);
        Self::ntt_layer::<16>(f, &Self::ZETAS[8..16]);
        Self::ntt_layer::<8>(f, &Self::ZETAS[16..32]);
        Self::ntt_layer::<4>(f, &Self::ZETAS[32..64]);
        Self::ntt_layer::<2>(f, &Self::ZETAS[64..128]);
        for a in f.iter_mut() {
            *a = Self::reduce(*a);
        }
    }

    fn ntt_layer<const LEN: usize>(f: &mut [i16; 256], zetas: &[i16]) {
        let (halves, _) = f.as_chunks_mut::<LEN>();
        let (blocks, _) = halves.as_chunks_mut::<2>();
        for ([lower, upper], &zeta) in blocks.iter_mut().zip(zetas) {
            for (a, b) in lower.iter_mut().zip(upper.iter_mut()) {
                let t = Self::montgomery_multiply(zeta, *b);
                *b = *a - t;
                *a += t;
            }
        }
    }

    // Algorithm 10
    fn inverse_ntt(f: &mut [i16; 256]) {
        Self::inverse_ntt_layer::<2>(f, &Self::ZETAS[64..128]);
        Self::inverse_ntt_layer::<4>(f, &Self::ZETAS[32..64]);
        Self::inverse_ntt_layer::<8>(f, &Self::ZETAS[16..32]);
        Self::inverse_ntt_layer::<16>(f, &Self::ZETAS[8..16]);
        Self::inverse_ntt_layer::<32>(f, &Self::ZETAS[4..8]);
        Self::inverse_ntt_layer::<64>(f, &Self::ZETAS[2..4]);
        Self::inverse_ntt_layer::<128>(f, &Self::ZETAS[1..2]);
        for a in f.iter_mut() {
            *a = Self::montgomery_multiply(*a, 512);
        }
    }

    fn inverse_ntt_layer<const LEN: usize>(f: &mut [i16; 256], zetas: &[i16]) {
        let (halves, _) = f.as_chunks_mut::<LEN>();
        let (blocks, _) = halves.as_chunks_mut::<2>();
        for ([lower, upper], &zeta) in blocks.iter_mut().zip(zetas.iter().rev()) {
            for (a, b) in lower.iter_mut().zip(upper.iter_mut()) {
                let t = *a;
                *a = Self::barrett_reduce(t + *b);
                *b = Self::montgomery_multiply(zeta, *b - t);
            }
        }
    }

    // Algorithm 11
    fn add_multiply_ntts(h: &mut [i16; 256], f: &[i16; 256], g: &[i16; 256]) {
        let (f, _) = f.as_chunks::<2>();
        let (g, _) = g.as_chunks::<2>();
        let (h, _) = h.as_chunks_mut::<2>();
        for (((&[a0, a1], &[b0, b1]), [c0, c1]), gamma) in f.iter().zip(g).zip(h).zip(Self::GAMMAS)
        {
            let (p0, p1) = Self::base_case_multiply(a0, a1, b0, b1, gamma);
            *c0 += p0;
            *c1 += p1;
        }
    }

    // Algorithm 12
    const fn base_case_multiply(a0: i16, a1: i16, b0: i16, b1: i16, gamma: i16) -> (i16, i16) {
        let b1_gamma = Self::montgomery_multiply(b1, gamma);
        let c0 = Self::montgomery_reduce(a0 as i32 * b0 as i32 + a1 as i32 * b1_gamma as i32);
        let c1 = Self::montgomery_reduce(a0 as i32 * b1 as i32 + a1 as i32 * b0 as i32);
        (
            Self::montgomery_multiply(c0, 1353),
            Self::montgomery_multiply(c1, 1353),
        )
    }

    // Algorithm 13
    fn k_pke_key_gen(d: &[u8], ek_pke: &mut [u8], dk_pke: &mut [u8]) {
        let seeds = Self::g(d, &[K as u8]);
        let (rho, sigma) = seeds.get().split_at(32);
        let mut n = 0;
        let mut s = [const { Secret([0i16; 256]) }; K];
        for poly in &mut s {
            Self::sample_poly(P::ETA1, sigma, &mut n, poly.get_mut());
            Self::ntt(poly.get_mut());
        }
        let (t_bytes, rho_bytes) = ek_pke.split_at_mut(384 * K);
        let (t_bytes, _) = t_bytes.as_chunks_mut::<384>();
        for (i, bytes) in t_bytes.iter_mut().enumerate() {
            let mut t = Secret::from([0i16; 256]);
            for (j, s) in s.iter().enumerate() {
                let a = Self::sample_ntt(rho, j as u8, i as u8);
                Self::add_multiply_ntts(t.get_mut(), &a, s.get());
            }
            let mut e = Secret::from([0i16; 256]);
            Self::sample_poly(P::ETA1, sigma, &mut n, e.get_mut());
            Self::ntt(e.get_mut());
            Self::add_poly(t.get_mut(), e.get());
            Self::byte_encode(12, t.get(), bytes);
        }
        rho_bytes.copy_from_slice(rho);
        let (s_bytes, _) = dk_pke.as_chunks_mut::<384>();
        for (s, bytes) in s.iter().zip(s_bytes) {
            Self::byte_encode(12, s.get(), bytes);
        }
    }

    // Algorithm 14
    #[allow(clippy::chunks_exact_to_as_chunks)]
    fn k_pke_encrypt(ek_pke: &[u8], m: &[u8], r: &[u8], c: &mut [u8]) {
        let mut n = 0;
        let (t_bytes, rho) = ek_pke.split_at(384 * K);
        let (t_bytes, _) = t_bytes.as_chunks::<384>();
        let mut y = [const { Secret([0i16; 256]) }; K];
        for poly in &mut y {
            Self::sample_poly(P::ETA1, r, &mut n, poly.get_mut());
            Self::ntt(poly.get_mut());
        }
        let (c1, c2) = c.split_at_mut(32 * P::DU * K);
        for (i, bytes) in c1.chunks_exact_mut(32 * P::DU).enumerate() {
            let mut u = Secret::from([0i16; 256]);
            for (j, y) in y.iter().enumerate() {
                let a = Self::sample_ntt(rho, i as u8, j as u8);
                Self::add_multiply_ntts(u.get_mut(), &a, y.get());
            }
            Self::inverse_ntt(u.get_mut());
            let mut e1 = Secret::from([0i16; 256]);
            Self::sample_poly(P::ETA2, r, &mut n, e1.get_mut());
            Self::add_poly(u.get_mut(), e1.get());
            for x in u.get_mut() {
                *x = Self::compress(P::DU, *x);
            }
            Self::byte_encode(P::DU, u.get(), bytes);
        }
        let mut e2 = Secret::from([0i16; 256]);
        Self::sample_poly(P::ETA2, r, &mut n, e2.get_mut());
        let mut mu = Secret::from([0i16; 256]);
        Self::byte_decode(1, m, mu.get_mut());
        for x in mu.get_mut() {
            *x = Self::decompress(1, *x);
        }
        let mut v = Secret::from([0i16; 256]);
        let mut t = [0i16; 256];
        for (bytes, y) in t_bytes.iter().zip(&y) {
            Self::byte_decode(12, bytes, &mut t);
            Self::add_multiply_ntts(v.get_mut(), &t, y.get());
        }
        Self::inverse_ntt(v.get_mut());
        Self::add_poly(v.get_mut(), e2.get());
        Self::add_poly(v.get_mut(), mu.get());
        for x in v.get_mut() {
            *x = Self::compress(P::DV, *x);
        }
        Self::byte_encode(P::DV, v.get(), c2);
    }

    // Algorithm 15
    #[allow(clippy::chunks_exact_to_as_chunks)]
    fn k_pke_decrypt(dk_pke: &[u8], c: &[u8]) -> Secret<[u8; 32]> {
        let (c1, c2) = c.split_at(32 * P::DU * K);
        let (s_chunks, _) = dk_pke.as_chunks::<384>();
        let mut w = Secret::from([0i16; 256]);
        let mut s = Secret::from([0i16; 256]);
        let mut u = [0i16; 256];
        for (u_bytes, s_bytes) in c1.chunks_exact(32 * P::DU).zip(s_chunks) {
            Self::byte_decode(P::DU, u_bytes, &mut u);
            for x in &mut u {
                *x = Self::decompress(P::DU, *x);
            }
            Self::ntt(&mut u);
            Self::byte_decode(12, s_bytes, s.get_mut());
            Self::add_multiply_ntts(w.get_mut(), s.get(), &u);
        }
        Self::inverse_ntt(w.get_mut());
        let mut v = [0i16; 256];
        Self::byte_decode(P::DV, c2, &mut v);
        for x in &mut v {
            *x = Self::decompress(P::DV, *x);
        }
        for (w, v) in w.get_mut().iter_mut().zip(&v) {
            *w = Self::barrett_reduce(*v - *w);
        }
        for x in w.get_mut() {
            *x = Self::compress(1, *x);
        }
        let mut m = Secret::from([0u8; 32]);
        Self::byte_encode(1, w.get(), m.as_mut());
        m
    }

    // Algorithm 16
    fn key_gen_internal(d: &[u8], z: &[u8], ek: &mut [u8], dk: &mut [u8]) {
        let (dk_pke, rest) = dk.split_at_mut(384 * K);
        Self::k_pke_key_gen(d, ek, dk_pke);
        let (ek_bytes, rest) = rest.split_at_mut(384 * K + 32);
        ek_bytes.copy_from_slice(ek);
        let (hash, z_bytes) = rest.split_at_mut(32);
        hash.copy_from_slice(&H::digest(ek));
        z_bytes.copy_from_slice(z);
    }

    // Algorithm 17
    pub(crate) fn encaps_internal(ek: &[u8], m: &[u8]) -> (Secret<[u8; 32]>, P::Ciphertext) {
        let derived = Self::g(m, &H::digest(ek));
        let (k, r) = derived.get().split_at(32);
        let mut result = (Secret::from([0u8; 32]), P::Ciphertext::new());
        let (key, c) = &mut result;
        key.as_mut().copy_from_slice(k);
        Self::k_pke_encrypt(ek, m, r, c.as_mut());
        result
    }

    // Algorithm 18
    pub(crate) fn decaps_internal(dk: &[u8], c: &[u8]) -> Secret<[u8; 32]> {
        let (dk_pke, rest) = dk.split_at(384 * K);
        let (ek_pke, rest) = rest.split_at(384 * K + 32);
        let (h, z) = rest.split_at(32);
        let m = Self::k_pke_decrypt(dk_pke, c);
        let derived = Self::g(m.as_ref(), h);
        let (k, r) = derived.get().split_at(32);
        let k_bar = Self::j(z, c);
        let mut c_prime = P::Ciphertext::new();
        Self::k_pke_encrypt(ek_pke, m.as_ref(), r, c_prime.as_mut());
        let reject = !Choice::eq_slice(c, c_prime.as_ref());
        let mut key = Secret::from(<[u8; 32]>::from_slice(k));
        reject.assign(key.as_mut(), k_bar.as_ref());
        key
    }

    // Section 7.2
    pub(crate) fn encapsulation_key_check(ek: &[u8]) -> bool {
        let (t_bytes, _) = ek[..384 * K].as_chunks::<384>();
        let mut f = [0i16; 256];
        let mut test = [0u8; 384];
        let mut valid = true;
        for bytes in t_bytes {
            Self::byte_decode(12, bytes, &mut f);
            Self::byte_encode(12, &f, &mut test);
            valid &= test == *bytes;
        }
        valid
    }

    // Section 7.3
    fn decapsulation_key_check(dk: &[u8]) -> bool {
        let (_, rest) = dk.split_at(384 * K);
        let (ek, rest) = rest.split_at(384 * K + 32);
        let (h, _) = rest.split_at(32);
        verify(&H::digest(ek), h)
    }

    fn sample_poly(eta: usize, seed: &[u8], n: &mut u8, f: &mut [i16; 256]) {
        Self::sample_poly_cbd(eta, Self::prf(eta, seed, *n).as_ref(), f);
        *n += 1;
    }

    fn g(a: &[u8], b: &[u8]) -> Secret<[u8; 64]> {
        let mut hasher = G::new();
        hasher.update(a);
        hasher.update(b);
        Secret::from(hasher.finalize())
    }

    fn j(z: &[u8], c: &[u8]) -> Secret<[u8; 32]> {
        let mut xof = F::new();
        xof.update(z);
        xof.update(c);
        let mut output = Secret::from([0u8; 32]);
        xof.finalize_into(output.as_mut());
        output
    }

    fn prf(eta: usize, s: &[u8], b: u8) -> Secret<[u8; 192]> {
        let mut xof = F::new();
        xof.update(s);
        xof.update(&[b]);
        let mut output = Secret::from([0u8; 192]);
        xof.finalize_into(&mut output.as_mut()[..64 * eta]);
        output
    }

    fn add_poly(f: &mut [i16; 256], g: &[i16; 256]) {
        for (a, b) in f.iter_mut().zip(g) {
            *a = Self::barrett_reduce(*a + *b);
        }
    }

    const fn montgomery_reduce(a: i32) -> i16 {
        let t = (a as i16).wrapping_mul(-3327);
        ((a - t as i32 * Self::Q as i32) >> 16) as i16
    }

    const fn montgomery_multiply(a: i16, b: i16) -> i16 {
        Self::montgomery_reduce(a as i32 * b as i32)
    }

    const fn barrett_reduce(a: i16) -> i16 {
        let t = ((20159 * a as i32 + (1 << 25)) >> 26) as i16;
        a.wrapping_sub(t.wrapping_mul(Self::Q))
    }

    const fn reduce(a: i16) -> i16 {
        let a = Self::barrett_reduce(a);
        a + ((a >> 15) & Self::Q)
    }

    const fn zeta_power(exponent: usize) -> i16 {
        let mut power = (1 << 16) % Self::Q as u32;
        let mut k = 0;
        while k < exponent {
            power = power * 17 % Self::Q as u32;
            k += 1;
        }
        power as i16
    }

    const fn bit_rev7(i: usize) -> usize {
        (i as u8).reverse_bits() as usize >> 1
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::csprngs::ChaCha20Rng, hex_literal::hex};

    #[test]
    fn test_ml_kem_512() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let (private_key, public_key) = MlKem512::generate_key_pair(&mut rng);
        assert_eq!(
            Sha3_256::digest(private_key.as_ref()),
            hex!("2e00df480767274d608997eba92e6b4133c91f9c9de6d6aa2f38cc2946072164")
        );
        assert_eq!(
            Sha3_256::digest(&public_key),
            hex!("9cb1db280beef5d046de6918f079fdeddd8d8a14cd736227499443dd3383531a")
        );
        assert_eq!(MlKem512::public_key(&private_key), public_key);
        let (shared_secret, ciphertext) = MlKem512::encapsulate(&public_key, &mut rng).unwrap();
        assert_eq!(
            Sha3_256::digest(&ciphertext),
            hex!("d4e809968ac004d569ffaefb0d209fd89c883e6febb94ede677150446302cc05")
        );
        assert_eq!(
            shared_secret.as_ref(),
            &hex!("bf24081ba824336a4c6dd6f5e1678c107b137d3a141610f2873b302f24e2eeb0")
        );
        let decapsulated = MlKem512::decapsulate(&private_key, &ciphertext).unwrap();
        assert_eq!(decapsulated.as_ref(), shared_secret.as_ref());
    }

    #[test]
    fn test_ml_kem_768() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let (private_key, public_key) = MlKem768::generate_key_pair(&mut rng);
        assert_eq!(
            Sha3_256::digest(private_key.as_ref()),
            hex!("43dd6e168692b2d7dffc7fa8da478ef1dd0513daf99773e54a688386723ae5d3")
        );
        assert_eq!(
            Sha3_256::digest(&public_key),
            hex!("24683eb57011480d8aa9b3113d4d648121886705d4fdd7f509f1284726e0d838")
        );
        assert_eq!(MlKem768::public_key(&private_key), public_key);
        let (shared_secret, ciphertext) = MlKem768::encapsulate(&public_key, &mut rng).unwrap();
        assert_eq!(
            Sha3_256::digest(&ciphertext),
            hex!("462995ace42b9e8ef78bf0b1cec8eaf247eb8ce2575ac6adfdb0f37fdb7af311")
        );
        assert_eq!(
            shared_secret.as_ref(),
            &hex!("a9bc3e359d3a3bdcbc30a9b61c35619e15bbf343d1042b7a34bc62488e97e491")
        );
        let decapsulated = MlKem768::decapsulate(&private_key, &ciphertext).unwrap();
        assert_eq!(decapsulated.as_ref(), shared_secret.as_ref());
    }

    #[test]
    fn test_ml_kem_1024() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let (private_key, public_key) = MlKem1024::generate_key_pair(&mut rng);
        assert_eq!(
            Sha3_256::digest(private_key.as_ref()),
            hex!("a0a8b06a25e3ca02e39cb1655f63ca8ab4f4f0e12e8a74db175a5f5c9601cb79")
        );
        assert_eq!(
            Sha3_256::digest(&public_key),
            hex!("77367d9beacbd301c1cdfec9fa052a01aa021c0f94a6e5f344f538152413951e")
        );
        assert_eq!(MlKem1024::public_key(&private_key), public_key);
        let (shared_secret, ciphertext) = MlKem1024::encapsulate(&public_key, &mut rng).unwrap();
        assert_eq!(
            Sha3_256::digest(&ciphertext),
            hex!("28a774a857949e82aa0c0b72ecb29b4a40fa1d9a49335403150521c9fe4d7297")
        );
        assert_eq!(
            shared_secret.as_ref(),
            &hex!("48c05576469ce86bc71e0f965b465b5a5a52f99fb32ed3411885e12b816a8144")
        );
        let decapsulated = MlKem1024::decapsulate(&private_key, &ciphertext).unwrap();
        assert_eq!(decapsulated.as_ref(), shared_secret.as_ref());
    }
}
