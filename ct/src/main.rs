mod valgrind;

use {
    std::hint::black_box,
    stedy::{
        Error, SecretBytes,
        aeads::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, XChaCha20Poly1305, XSalsa20Poly1305},
        constant_time_eq,
        csprngs::{Aes256CtrRng, ChaCha20Rng, HmacDrbg},
        elliptic_curves::Ristretto255,
        encoding::{Encoding, decode, encode},
        hashes::{Blake2b512, Blake2s256, Sha3_256, Sha256, Sha512},
        kdfs::{Argon2, Argon2Params, Argon2Variant, Hkdf, Pbkdf2},
        kems::{MlKem512, MlKem768, MlKem1024, XWing},
        key_exchange::{self, X25519},
        macs::Hmac,
        padding::{pad_to_block, unpad},
        secret_sharing::Shamir,
        signatures::{self, Ed25519, Ed25519ph, MlDsa44, MlDsa65, MlDsa87},
        traits::{Aead, ByteArray, CryptoRng, HashFunction, Kem, KeyExchange, SignatureScheme},
    },
    valgrind::{classify, declassify},
};

struct SecretRng(ChaCha20Rng);

impl SecretRng {
    fn new() -> Self {
        Self(ChaCha20Rng::from(&[42u8; 96]))
    }
}

impl CryptoRng for SecretRng {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.0.fill(bytes)?;
        classify(bytes);
        Ok(())
    }
}

fn public<T: ?Sized>(value: &T) {
    declassify(value);
    black_box(value);
}

fn consume<T: ?Sized>(value: &T) {
    black_box(value);
}

static TABLE: [u8; 256] = [0; 256];

#[inline(never)]
fn control() {
    let secret = [1u8; 2];
    classify(&secret);
    let looked_up = black_box(&TABLE)[usize::from(secret[0])];
    let mut counted = 0u8;
    for _ in 0..secret[1] {
        counted = black_box(counted.wrapping_add(1));
    }
    public(&(looked_up ^ counted));
}

fn equality() {
    let a = [3u8; 32];
    classify(&a);
    public(&constant_time_eq(&a, &[4u8; 32]));
    let a = SecretBytes::from([3u8; 32]);
    classify(a.as_ref());
    public(&(a == [4u8; 32]));
}

fn key_exchange<X: KeyExchange>() {
    let mut rng = SecretRng::new();
    let (private_key, public_key) = X::generate_key_pair(&mut rng).unwrap();
    public(public_key.as_ref());
    let (_, peer_public_key) = X::generate_key_pair(&mut rng).unwrap();
    public(peer_public_key.as_ref());
    public(&X::public_key(&private_key));
    consume(&X::key_exchange(&private_key, &peer_public_key));
}

fn signature_scheme<S: SignatureScheme>() {
    let mut rng = SecretRng::new();
    let (private_key, public_key) = S::generate_key_pair(&mut rng).unwrap();
    public(public_key.as_ref());
    public(&S::public_key(&private_key));
    public(&S::sign(&private_key, b"message"));
}

fn kem<K: Kem>() {
    let mut rng = SecretRng::new();
    let (private_key, public_key) = K::generate_key_pair(&mut rng).unwrap();
    public(public_key.as_ref());
    let (shared_secret, ciphertext) = K::encapsulate(&public_key, &mut rng).unwrap();
    public(ciphertext.as_ref());
    consume(shared_secret.as_ref());
    consume(&K::decapsulate(&private_key, &ciphertext));
    let mut corrupted = ciphertext.clone();
    corrupted[0] ^= 1;
    consume(&K::decapsulate(&private_key, &corrupted));
}

fn aead<A: Aead>() {
    let mut rng = SecretRng::new();
    let key = A::generate_key(&mut rng).unwrap();
    let nonce = A::Nonce::new();
    let mut message = [7u8; 100];
    classify(&message);
    let tag = A::encrypt(&key, &nonce, Some(b"aad"), &mut message).unwrap();
    public(&message);
    public(tag.as_ref());
    let mut decrypted = message;
    public(&A::decrypt(
        &key,
        &nonce,
        Some(b"aad"),
        &mut decrypted,
        &tag,
    ));
    consume(&decrypted);
    let mut forged = tag.clone();
    forged[0] ^= 1;
    let mut rejected = message;
    public(&A::decrypt(
        &key,
        &nonce,
        Some(b"aad"),
        &mut rejected,
        &forged,
    ));
}

fn ed25519ph() {
    let seed = [5u8; 32];
    classify(&seed);
    let (private_key, public_key) = Ed25519::key_pair(&seed);
    public(&public_key);
    let mut signer = Ed25519ph::new();
    signer.update(b"message");
    public(&signer.sign(&private_key, b"context"));
}

fn xsalsa20_poly1305() {
    let mut rng = SecretRng::new();
    let key = XSalsa20Poly1305::generate_key(&mut rng).unwrap();
    let nonce = [0u8; 24];
    let mut message = [7u8; 100];
    classify(&message);
    let tag = XSalsa20Poly1305::encrypt(&key, &nonce, None, &mut message).unwrap();
    public(&message);
    public(&tag);
    let mut decrypted = message;
    public(&XSalsa20Poly1305::decrypt(
        &key,
        &nonce,
        None,
        &mut decrypted,
        &tag,
    ));
    consume(&decrypted);
}

fn hash<H: HashFunction>() {
    let message = [9u8; 300];
    classify(&message);
    consume(H::digest(&message).as_ref());
}

fn macs() {
    let key = [1u8; 32];
    classify(&key);
    let mut mac = Hmac::<Sha256>::new(&key);
    mac.update(b"message");
    let code = mac.clone().finalize();
    public(&code);
    public(&mac.verify(&code));
    let mut mac = Blake2b512::new(Some(&key)).unwrap();
    mac.update(b"message");
    let code = mac.clone().finalize();
    public(&code);
    public(&mac.verify(&code));
}

fn kdfs() {
    let secret = [2u8; 32];
    classify(&secret);
    let mut output = [0u8; 64];
    public(&Hkdf::<Sha256>::derive(
        &secret,
        Some(b"salt"),
        Some(b"info"),
        &mut output,
    ));
    consume(&output);
    public(&Pbkdf2::<Sha256>::derive(&secret, b"salt", 2, &mut output));
    consume(&output);
    public(&Argon2::derive(
        Argon2Params::new(Argon2Variant::Argon2i)
            .memory(32)
            .passes(1)
            .lanes(1)
            .threads(1),
        &secret,
        b"saltsalt",
        None,
        None,
        &mut output[..32],
    ));
    consume(&output);
}

fn encoding() {
    let secret = [0x5au8; 33];
    classify(&secret);
    for encoding in [
        Encoding::Hex,
        Encoding::Base32,
        Encoding::Base64,
        Encoding::Base64UrlUnpadded,
    ] {
        let mut encoded = [0u8; 128];
        let encoded = encode(encoding, &secret, &mut encoded).unwrap();
        let mut decoded = [0u8; 64];
        let decoded = decode(encoding, encoded, &mut decoded).map(<[u8]>::len);
        public(&decoded);
    }
}

fn padding() {
    let secret = [3u8; 21];
    classify(&secret);
    let mut buffer = [0u8; 64];
    let padded = pad_to_block(&secret, &mut buffer, 16).unwrap();
    public(&unpad(padded).map(<[u8]>::len));
}

fn shamir() {
    let mut rng = SecretRng::new();
    let secret = [4u8; 32];
    classify(&secret);
    let mut output = [0u8; 5 * 36];
    let shares = Shamir::split::<3, 5>(&mut rng, &secret, &mut output).unwrap();
    let mut combined = [0u8; 32];
    let combined = Shamir::combine([shares[0], shares[2], shares[4]], &mut combined).unwrap();
    consume(combined);
}

fn csprngs() {
    let seed = [6u8; 96];
    classify(&seed);
    let mut output = [0u8; 100];
    ChaCha20Rng::from(&seed).fill(&mut output).unwrap();
    consume(&output);
    Aes256CtrRng::from(&seed).fill(&mut output).unwrap();
    consume(&output);
    let mut drbg = HmacDrbg::<Sha256>::instantiate(&seed[..32], &seed[32..48]);
    drbg.fill(&mut output).unwrap();
    consume(&output);
}

fn ristretto255() {
    let mut rng = SecretRng::new();
    let scalar = Ristretto255::generate_scalar(&mut rng).unwrap();
    let other = Ristretto255::generate_scalar(&mut rng).unwrap();
    public(&Ristretto255::scalar_mult_base(&scalar));
    let base = Ristretto255::scalar_mult_base(&[9u8; 32]).unwrap();
    consume(&Ristretto255::scalar_mult(&other, &base));
    consume(&Ristretto255::scalar_add(&scalar, &other));
    consume(&Ristretto255::scalar_mul(&scalar, &other));
    consume(&Ristretto255::scalar_negate(&scalar));
    consume(&Ristretto255::scalar_invert(&scalar));
    let wide = [8u8; 64];
    classify(&wide);
    consume(&Ristretto255::scalar_reduce(&wide));
}

const CHECKS: &[(&str, fn())] = &[
    ("equality", equality),
    ("x25519", key_exchange::<X25519>),
    ("p256_ecdh", key_exchange::<key_exchange::P256>),
    ("p384_ecdh", key_exchange::<key_exchange::P384>),
    ("p521_ecdh", key_exchange::<key_exchange::P521>),
    ("ed25519", signature_scheme::<Ed25519>),
    ("ecdsa_p256", signature_scheme::<signatures::P256>),
    ("ecdsa_p384", signature_scheme::<signatures::P384>),
    ("ecdsa_p521", signature_scheme::<signatures::P521>),
    ("ml_dsa_44", signature_scheme::<MlDsa44>),
    ("ml_dsa_65", signature_scheme::<MlDsa65>),
    ("ml_dsa_87", signature_scheme::<MlDsa87>),
    ("ml_kem_512", kem::<MlKem512>),
    ("ml_kem_768", kem::<MlKem768>),
    ("ml_kem_1024", kem::<MlKem1024>),
    ("x_wing", kem::<XWing>),
    ("aes_128_gcm", aead::<Aes128Gcm>),
    ("aes_256_gcm", aead::<Aes256Gcm>),
    ("chacha20_poly1305", aead::<ChaCha20Poly1305>),
    ("xchacha20_poly1305", aead::<XChaCha20Poly1305>),
    ("xsalsa20_poly1305", xsalsa20_poly1305),
    ("ed25519ph", ed25519ph),
    ("sha256", hash::<Sha256>),
    ("sha512", hash::<Sha512>),
    ("sha3_256", hash::<Sha3_256>),
    ("blake2b_512", hash::<Blake2b512>),
    ("blake2s_256", hash::<Blake2s256>),
    ("macs", macs),
    ("kdfs", kdfs),
    ("encoding", encoding),
    ("padding", padding),
    ("shamir", shamir),
    ("csprngs", csprngs),
    ("ristretto255", ristretto255),
];

fn main() {
    let filter = std::env::args().nth(1);
    if !valgrind::running() {
        eprintln!("note: not running under valgrind, so nothing is checked");
    }
    if filter.as_deref() == Some("control") {
        control();
        return;
    }
    for (name, check) in CHECKS {
        if filter.as_deref().is_none_or(|filter| name.contains(filter)) {
            eprintln!("check {name}");
            check();
        }
    }
}
