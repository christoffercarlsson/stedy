use {
    crate::{compress_point, load, Summary, TestFile, TestResult},
    serde::{de::DeserializeOwned, Deserialize},
    stedy::signatures::{Ed25519, Ed448, MlDsa44, MlDsa65, MlDsa87, P256, P384, P521},
};

#[cfg(feature = "hazmat")]
use crate::FixedRng;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaGroup {
    public_key: EcdsaKey,
}

#[derive(Deserialize)]
struct EcdsaKey {
    #[serde(deserialize_with = "crate::hex")]
    uncompressed: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EddsaGroup {
    public_key: EddsaKey,
}

#[derive(Deserialize)]
struct EddsaKey {
    #[serde(deserialize_with = "crate::hex")]
    pk: Vec<u8>,
}

#[derive(Deserialize)]
struct VerifyCase {
    #[serde(deserialize_with = "crate::hex")]
    msg: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    sig: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlDsaVerifyGroup {
    #[serde(deserialize_with = "crate::hex")]
    public_key: Vec<u8>,
}

#[derive(Deserialize)]
struct MlDsaVerifyCase {
    #[serde(deserialize_with = "crate::hex")]
    msg: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    sig: Vec<u8>,
    #[serde(default, deserialize_with = "crate::hex_opt")]
    ctx: Option<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MlDsaSignGroup {
    #[serde(default, deserialize_with = "crate::hex_opt")]
    private_seed: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "crate::hex_opt")]
    private_key: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "crate::hex_opt")]
    public_key: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct MlDsaSignCase {
    #[serde(default, deserialize_with = "crate::hex_opt")]
    msg: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "crate::hex_opt")]
    mu: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "crate::hex_opt")]
    rnd: Option<Vec<u8>>,
    #[serde(deserialize_with = "crate::hex")]
    sig: Vec<u8>,
    #[serde(default, deserialize_with = "crate::hex_opt")]
    ctx: Option<Vec<u8>>,
}

type Verify = fn(&[u8], &[u8], &[u8]) -> bool;
type VerifyWithContext = fn(&[u8], &[u8], &[u8], &[u8]) -> bool;
type KeyPair = fn(&[u8]) -> Option<(Vec<u8>, Vec<u8>)>;
type Sign = fn(&[u8], &[u8]) -> Option<Vec<u8>>;
type SignWithContext = fn(&[u8], &[u8], &[u8]) -> Option<Vec<u8>>;
#[cfg(feature = "hazmat")]
type SignHedged = fn(&[u8], &[u8], &[u8]) -> Option<Vec<u8>>;
#[cfg(feature = "hazmat")]
type SignHedgedWithContext = fn(&[u8], &[u8], &[u8], &[u8]) -> Option<Vec<u8>>;

struct MlDsa {
    name: &'static str,
    verify_json: &'static str,
    sign_seed_json: &'static str,
    sign_noseed_json: &'static str,
    key_pair: KeyPair,
    sign: SignWithContext,
    sign_mu: Sign,
    #[cfg(feature = "hazmat")]
    sign_hedged: SignHedgedWithContext,
    #[cfg(feature = "hazmat")]
    sign_mu_hedged: SignHedged,
    verify: VerifyWithContext,
}

macro_rules! ecdsa {
    ($ecdsa:ty, $point:literal) => {
        |message: &[u8], public_key: &[u8], signature: &[u8]| {
            let verify = || {
                let public_key = compress_point::<$point>(public_key)?;
                Some(<$ecdsa>::verify(
                    message,
                    &public_key,
                    &signature.try_into().ok()?,
                ))
            };
            verify().unwrap_or(false)
        }
    };
}

macro_rules! ml_dsa {
    ($ml_dsa:ty, $name:literal) => {
        MlDsa {
            name: $name,
            verify_json: include_str!(concat!("vectors/", $name, "_verify_test.json")),
            sign_seed_json: include_str!(concat!("vectors/", $name, "_sign_seed_test.json")),
            sign_noseed_json: include_str!(concat!("vectors/", $name, "_sign_noseed_test.json")),
            key_pair: |seed: &[u8]| {
                let (private_key, public_key) = <$ml_dsa>::key_pair(&seed.try_into().ok()?);
                Some((private_key.to_vec(), public_key.to_vec()))
            },
            sign: |private_key: &[u8], message: &[u8], context: &[u8]| {
                let private_key = private_key.try_into().ok()?;
                let signature =
                    <$ml_dsa>::sign_deterministic_with_context(&private_key, message, context)?;
                Some(signature.to_vec())
            },
            sign_mu: |private_key: &[u8], mu: &[u8]| {
                let private_key = private_key.try_into().ok()?;
                let mu = mu.try_into().ok()?;
                Some(<$ml_dsa>::sign_external_mu_deterministic(&private_key, &mu).to_vec())
            },
            #[cfg(feature = "hazmat")]
            sign_hedged: |private_key: &[u8], message: &[u8], context: &[u8], rnd: &[u8]| {
                let private_key = private_key.try_into().ok()?;
                let signature = <$ml_dsa>::sign_with_context(
                    &private_key,
                    message,
                    context,
                    &mut FixedRng(rnd),
                )?;
                Some(signature.to_vec())
            },
            #[cfg(feature = "hazmat")]
            sign_mu_hedged: |private_key: &[u8], mu: &[u8], rnd: &[u8]| {
                let private_key = private_key.try_into().ok()?;
                let mu = mu.try_into().ok()?;
                Some(<$ml_dsa>::sign_external_mu(&private_key, &mu, &mut FixedRng(rnd)).to_vec())
            },
            verify: |message: &[u8], context: &[u8], public_key: &[u8], signature: &[u8]| {
                let verify = || {
                    let public_key = public_key.try_into().ok()?;
                    let signature = signature.try_into().ok()?;
                    Some(<$ml_dsa>::verify_with_context(
                        message,
                        context,
                        &public_key,
                        &signature,
                    ))
                };
                verify().unwrap_or(false)
            },
        }
    };
}

fn run_verify<G: DeserializeOwned>(
    name: &str,
    json: &str,
    public_key: fn(&G) -> &[u8],
    verify: Verify,
) {
    let file: TestFile<G, VerifyCase> = load(json);
    let mut summary = Summary::new(name, &file);
    for group in &file.test_groups {
        for case in &group.tests {
            let c = &case.case;
            let accepted = verify(&c.msg, public_key(&group.group), &c.sig);
            summary.check(case, case.result.accepts(accepted));
        }
    }
    summary.finish();
}

fn run_ml_dsa_verify(ml_dsa: &MlDsa) {
    let file: TestFile<MlDsaVerifyGroup, MlDsaVerifyCase> = load(ml_dsa.verify_json);
    let mut summary = Summary::new(&format!("{}_verify", ml_dsa.name), &file);
    for group in &file.test_groups {
        for case in &group.tests {
            let c = &case.case;
            let context = c.ctx.as_deref().unwrap_or_default();
            let accepted = (ml_dsa.verify)(&c.msg, context, &group.group.public_key, &c.sig);
            summary.check(case, case.result.accepts(accepted));
        }
    }
    summary.finish();
}

fn run_ml_dsa_sign(ml_dsa: &MlDsa, name: &str, json: &str) {
    let file: TestFile<MlDsaSignGroup, MlDsaSignCase> = load(json);
    let mut summary = Summary::new(name, &file);
    for group in &file.test_groups {
        let g = &group.group;
        let (private_key, public_key_ok) = match (&g.private_seed, &g.private_key) {
            (Some(seed), _) => match (ml_dsa.key_pair)(seed) {
                Some((private_key, public_key)) => (
                    Some(private_key),
                    g.public_key
                        .as_ref()
                        .is_none_or(|expected| *expected == public_key),
                ),
                None => (None, true),
            },
            (None, private_key) => (private_key.clone(), true),
        };
        for case in &group.tests {
            let c = &case.case;
            if case.has_flag("InvalidPrivateKey") {
                summary.skip();
                continue;
            }
            let Some(private_key) = &private_key else {
                summary.check(case, case.result == TestResult::Invalid);
                continue;
            };
            let context = c.ctx.as_deref().unwrap_or_default();
            let mut signatures = Vec::new();
            if let Some(message) = &c.msg {
                match &c.rnd {
                    None => signatures.push((ml_dsa.sign)(private_key, message, context)),
                    #[cfg(feature = "hazmat")]
                    Some(rnd) => {
                        signatures.push((ml_dsa.sign_hedged)(private_key, message, context, rnd))
                    }
                    #[cfg(not(feature = "hazmat"))]
                    Some(_) => {}
                }
            }
            if let Some(mu) = &c.mu {
                match &c.rnd {
                    None => signatures.push((ml_dsa.sign_mu)(private_key, mu)),
                    #[cfg(feature = "hazmat")]
                    Some(rnd) => signatures.push((ml_dsa.sign_mu_hedged)(private_key, mu, rnd)),
                    #[cfg(not(feature = "hazmat"))]
                    Some(_) => {}
                }
            }
            if signatures.is_empty() {
                summary.skip();
                continue;
            }
            let ok = public_key_ok
                && signatures
                    .iter()
                    .all(|signature| case.result.matches(signature.as_deref(), &c.sig));
            summary.check(case, ok);
        }
    }
    summary.finish();
}

fn run_ml_dsa(ml_dsa: &MlDsa) {
    run_ml_dsa_verify(ml_dsa);
    run_ml_dsa_sign(
        ml_dsa,
        &format!("{}_sign_seed", ml_dsa.name),
        ml_dsa.sign_seed_json,
    );
    run_ml_dsa_sign(
        ml_dsa,
        &format!("{}_sign_noseed", ml_dsa.name),
        ml_dsa.sign_noseed_json,
    );
}

macro_rules! eddsa {
    ($eddsa:ty) => {
        |message: &[u8], public_key: &[u8], signature: &[u8]| {
            let verify = || {
                let public_key = public_key.try_into().ok()?;
                let signature = signature.try_into().ok()?;
                Some(<$eddsa>::verify(message, &public_key, &signature))
            };
            verify().unwrap_or(false)
        }
    };
}

#[test]
fn ed25519() {
    run_verify(
        "ed25519",
        include_str!("vectors/ed25519_test.json"),
        |group: &EddsaGroup| &group.public_key.pk,
        eddsa!(Ed25519),
    );
}

#[test]
fn ed448() {
    run_verify(
        "ed448",
        include_str!("vectors/ed448_test.json"),
        |group: &EddsaGroup| &group.public_key.pk,
        eddsa!(Ed448),
    );
}

#[test]
fn ecdsa_p256() {
    run_verify(
        "ecdsa_secp256r1_sha256_p1363",
        include_str!("vectors/ecdsa_secp256r1_sha256_p1363_test.json"),
        |group: &EcdsaGroup| &group.public_key.uncompressed,
        ecdsa!(P256, 33),
    );
}

#[test]
fn ecdsa_p384() {
    run_verify(
        "ecdsa_secp384r1_sha384_p1363",
        include_str!("vectors/ecdsa_secp384r1_sha384_p1363_test.json"),
        |group: &EcdsaGroup| &group.public_key.uncompressed,
        ecdsa!(P384, 49),
    );
}

#[test]
fn ecdsa_p521() {
    run_verify(
        "ecdsa_secp521r1_sha512_p1363",
        include_str!("vectors/ecdsa_secp521r1_sha512_p1363_test.json"),
        |group: &EcdsaGroup| &group.public_key.uncompressed,
        ecdsa!(P521, 67),
    );
}

#[test]
fn ml_dsa_44() {
    run_ml_dsa(&ml_dsa!(MlDsa44, "mldsa_44"));
}

#[test]
fn ml_dsa_65() {
    run_ml_dsa(&ml_dsa!(MlDsa65, "mldsa_65"));
}

#[test]
fn ml_dsa_87() {
    run_ml_dsa(&ml_dsa!(MlDsa87, "mldsa_87"));
}
