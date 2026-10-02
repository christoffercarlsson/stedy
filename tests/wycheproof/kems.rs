use {
    crate::{load, NoGroup, Summary, TestFile, TestResult},
    serde::Deserialize,
    stedy::kems::{MlKem1024, MlKem512, MlKem768},
};

#[cfg(feature = "hazmat")]
use crate::FixedRng;

#[derive(Deserialize)]
struct Case {
    #[serde(default, deserialize_with = "crate::hex_opt")]
    seed: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "crate::hex_opt")]
    ek: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "crate::hex_opt")]
    dk: Option<Vec<u8>>,
    #[cfg(feature = "hazmat")]
    #[serde(default, deserialize_with = "crate::hex_opt")]
    m: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "crate::hex_opt")]
    c: Option<Vec<u8>>,
    #[serde(rename = "K", default, deserialize_with = "crate::hex_opt")]
    k: Option<Vec<u8>>,
}

type KeyPair = fn(&[u8]) -> Option<(Vec<u8>, Vec<u8>)>;
#[cfg(feature = "hazmat")]
type Encapsulate = fn(&[u8], &[u8]) -> Option<(Vec<u8>, Vec<u8>)>;
type Decapsulate = fn(&[u8], &[u8]) -> Option<Vec<u8>>;

struct MlKem {
    name: &'static str,
    basic_json: &'static str,
    #[cfg(feature = "hazmat")]
    encaps_json: &'static str,
    keygen_json: &'static str,
    decaps_json: &'static str,
    key_pair: KeyPair,
    #[cfg(feature = "hazmat")]
    encapsulate: Encapsulate,
    decapsulate: Decapsulate,
}

macro_rules! ml_kem {
    ($ml_kem:ty, $name:literal) => {
        MlKem {
            name: $name,
            basic_json: include_str!(concat!("vectors/", $name, "_test.json")),
            #[cfg(feature = "hazmat")]
            encaps_json: include_str!(concat!("vectors/", $name, "_encaps_test.json")),
            keygen_json: include_str!(concat!("vectors/", $name, "_keygen_seed_test.json")),
            decaps_json: include_str!(concat!(
                "vectors/",
                $name,
                "_semi_expanded_decaps_test.json"
            )),
            key_pair: |seed: &[u8]| {
                let (private_key, public_key) = <$ml_kem>::key_pair(&seed.try_into().ok()?);
                Some((private_key.to_vec(), public_key.to_vec()))
            },
            #[cfg(feature = "hazmat")]
            encapsulate: |public_key: &[u8], m: &[u8]| {
                let public_key = public_key.try_into().ok()?;
                let (shared_secret, ciphertext) =
                    <$ml_kem>::encapsulate(&public_key, &mut FixedRng(m))?;
                Some((shared_secret.to_vec(), ciphertext.to_vec()))
            },
            decapsulate: |private_key: &[u8], ciphertext: &[u8]| {
                let private_key = private_key.try_into().ok()?;
                let ciphertext = ciphertext.try_into().ok()?;
                Some(<$ml_kem>::decapsulate(&private_key, &ciphertext)?.to_vec())
            },
        }
    };
}

fn strict(result: TestResult, output: Option<&[u8]>, expected: Option<&[u8]>) -> bool {
    match result {
        TestResult::Valid => output.is_some() && output == expected,
        TestResult::Invalid => output.is_none(),
        TestResult::Acceptable => true,
    }
}

fn run_basic(ml_kem: &MlKem) {
    let file: TestFile<NoGroup, Case> = load(ml_kem.basic_json);
    let mut summary = Summary::new(ml_kem.name, &file);
    for group in &file.test_groups {
        for case in &group.tests {
            let c = &case.case;
            let keys = c.seed.as_deref().and_then(ml_kem.key_pair);
            let ok = match keys {
                Some((private_key, public_key)) => {
                    let shared_secret =
                        c.c.as_deref()
                            .and_then(|ciphertext| (ml_kem.decapsulate)(&private_key, ciphertext));
                    c.ek.as_deref()
                        .is_none_or(|expected| expected == public_key)
                        && strict(case.result, shared_secret.as_deref(), c.k.as_deref())
                }
                None => case.result == TestResult::Invalid,
            };
            summary.check(case, ok);
        }
    }
    summary.finish();
}

#[cfg(feature = "hazmat")]
fn run_encaps(ml_kem: &MlKem) {
    let file: TestFile<NoGroup, Case> = load(ml_kem.encaps_json);
    let mut summary = Summary::new(&format!("{}_encaps", ml_kem.name), &file);
    for group in &file.test_groups {
        for case in &group.tests {
            let c = &case.case;
            let output =
                c.ek.as_deref()
                    .zip(c.m.as_deref())
                    .and_then(|(public_key, m)| (ml_kem.encapsulate)(public_key, m));
            let ok = match &output {
                Some((shared_secret, ciphertext)) => {
                    strict(case.result, Some(shared_secret), c.k.as_deref())
                        && strict(case.result, Some(ciphertext), c.c.as_deref())
                }
                None => strict(case.result, None, None),
            };
            summary.check(case, ok);
        }
    }
    summary.finish();
}

fn run_keygen(ml_kem: &MlKem) {
    let file: TestFile<NoGroup, Case> = load(ml_kem.keygen_json);
    let mut summary = Summary::new(&format!("{}_keygen_seed", ml_kem.name), &file);
    for group in &file.test_groups {
        for case in &group.tests {
            let c = &case.case;
            let ok = match c.seed.as_deref().and_then(ml_kem.key_pair) {
                Some((private_key, public_key)) => {
                    strict(case.result, Some(&private_key), c.dk.as_deref())
                        && strict(case.result, Some(&public_key), c.ek.as_deref())
                }
                None => strict(case.result, None, None),
            };
            summary.check(case, ok);
        }
    }
    summary.finish();
}

fn run_decaps(ml_kem: &MlKem) {
    let file: TestFile<NoGroup, Case> = load(ml_kem.decaps_json);
    let mut summary = Summary::new(&format!("{}_semi_expanded_decaps", ml_kem.name), &file);
    for group in &file.test_groups {
        for case in &group.tests {
            let c = &case.case;
            let shared_secret =
                c.dk.as_deref()
                    .zip(c.c.as_deref())
                    .and_then(|(private_key, ciphertext)| {
                        (ml_kem.decapsulate)(private_key, ciphertext)
                    });
            summary.check(
                case,
                strict(case.result, shared_secret.as_deref(), c.k.as_deref()),
            );
        }
    }
    summary.finish();
}

fn run(ml_kem: &MlKem) {
    run_basic(ml_kem);
    #[cfg(feature = "hazmat")]
    run_encaps(ml_kem);
    run_keygen(ml_kem);
    run_decaps(ml_kem);
}

#[test]
fn ml_kem_512() {
    run(&ml_kem!(MlKem512, "mlkem_512"));
}

#[test]
fn ml_kem_768() {
    run(&ml_kem!(MlKem768, "mlkem_768"));
}

#[test]
fn ml_kem_1024() {
    run(&ml_kem!(MlKem1024, "mlkem_1024"));
}
