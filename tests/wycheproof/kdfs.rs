use {
    crate::{load, NoGroup, Summary, TestFile},
    serde::Deserialize,
    stedy::{
        hashes::{Sha256, Sha384, Sha512},
        kdfs::{pbkdf2, Hkdf},
        macs::Hmac,
    },
};

#[cfg(feature = "hazmat")]
use stedy::hashes::Sha1;

#[derive(Deserialize)]
struct HkdfCase {
    #[serde(deserialize_with = "crate::hex")]
    ikm: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    salt: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    info: Vec<u8>,
    size: usize,
    #[serde(deserialize_with = "crate::hex")]
    okm: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pbkdf2Case {
    #[serde(deserialize_with = "crate::hex")]
    password: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    salt: Vec<u8>,
    iteration_count: usize,
    dk_len: usize,
    #[serde(deserialize_with = "crate::hex")]
    dk: Vec<u8>,
}

type Expand = fn(&[u8], &[u8], &[u8], &mut [u8]) -> bool;
type Derive = fn(&[u8], &[u8], usize, &mut [u8]);

macro_rules! hkdf {
    ($hash:ty) => {
        |ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]| {
            Hkdf::<$hash>::hkdf(ikm, Some(salt), Some(info), okm)
        }
    };
}

macro_rules! pbkdf2_hmac {
    ($hash:ty) => {
        |password: &[u8], salt: &[u8], iterations: usize, output: &mut [u8]| {
            pbkdf2::<Hmac<$hash>>(password, salt, iterations, output)
        }
    };
}

fn run_hkdf(name: &str, json: &str, expand: Expand) {
    let file: TestFile<NoGroup, HkdfCase> = load(json);
    let mut summary = Summary::new(name, &file);
    for group in &file.test_groups {
        for case in &group.tests {
            let c = &case.case;
            let mut okm = vec![0u8; c.size];
            let derived = expand(&c.ikm, &c.salt, &c.info, &mut okm);
            let output = derived.then_some(okm.as_slice());
            summary.check(case, case.result.matches(output, &c.okm));
        }
    }
    summary.finish();
}

fn run_pbkdf2(name: &str, json: &str, derive: Derive) {
    let file: TestFile<NoGroup, Pbkdf2Case> = load(json);
    let mut summary = Summary::new(name, &file);
    for group in &file.test_groups {
        for case in &group.tests {
            if cfg!(debug_assertions) && case.has_flag("LargeIterationCount") {
                summary.skip();
                continue;
            }
            let c = &case.case;
            let mut dk = vec![0u8; c.dk_len];
            derive(&c.password, &c.salt, c.iteration_count, &mut dk);
            summary.check(case, case.result.matches(Some(&dk), &c.dk));
        }
    }
    summary.finish();
}

#[cfg(feature = "hazmat")]
#[test]
fn hkdf_sha1() {
    run_hkdf(
        "hkdf_sha1",
        include_str!("vectors/hkdf_sha1_test.json"),
        hkdf!(Sha1),
    );
}

#[test]
fn hkdf_sha256() {
    run_hkdf(
        "hkdf_sha256",
        include_str!("vectors/hkdf_sha256_test.json"),
        hkdf!(Sha256),
    );
}

#[test]
fn hkdf_sha384() {
    run_hkdf(
        "hkdf_sha384",
        include_str!("vectors/hkdf_sha384_test.json"),
        hkdf!(Sha384),
    );
}

#[test]
fn hkdf_sha512() {
    run_hkdf(
        "hkdf_sha512",
        include_str!("vectors/hkdf_sha512_test.json"),
        hkdf!(Sha512),
    );
}

#[cfg(feature = "hazmat")]
#[test]
fn pbkdf2_hmac_sha1() {
    run_pbkdf2(
        "pbkdf2_hmacsha1",
        include_str!("vectors/pbkdf2_hmacsha1_test.json"),
        pbkdf2_hmac!(Sha1),
    );
}

#[test]
fn pbkdf2_hmac_sha256() {
    run_pbkdf2(
        "pbkdf2_hmacsha256",
        include_str!("vectors/pbkdf2_hmacsha256_test.json"),
        pbkdf2_hmac!(Sha256),
    );
}

#[test]
fn pbkdf2_hmac_sha384() {
    run_pbkdf2(
        "pbkdf2_hmacsha384",
        include_str!("vectors/pbkdf2_hmacsha384_test.json"),
        pbkdf2_hmac!(Sha384),
    );
}

#[test]
fn pbkdf2_hmac_sha512() {
    run_pbkdf2(
        "pbkdf2_hmacsha512",
        include_str!("vectors/pbkdf2_hmacsha512_test.json"),
        pbkdf2_hmac!(Sha512),
    );
}
