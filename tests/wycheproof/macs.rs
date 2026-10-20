use {
    crate::{Summary, TestFile, load},
    serde::Deserialize,
    stedy::{
        hashes::{Sha3_256, Sha3_384, Sha3_512, Sha256, Sha384, Sha512},
        macs::Hmac,
    },
};

#[cfg(feature = "hazmat")]
use stedy::hashes::{Sha1, Sha3_224};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Group {
    tag_size: usize,
}

#[derive(Deserialize)]
struct Case {
    #[serde(deserialize_with = "crate::hex")]
    key: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    msg: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    tag: Vec<u8>,
}

type Mac = fn(&[u8], &[u8], &mut [u8]);
type Verify = fn(&[u8], &[u8], &[u8]) -> Option<bool>;

macro_rules! hmac {
    ($hash:ty) => {
        (
            |key: &[u8], message: &[u8], tag: &mut [u8]| {
                let mut mac = Hmac::<$hash>::new(key);
                mac.update(message);
                mac.finalize_into(tag);
            },
            |key: &[u8], message: &[u8], tag: &[u8]| {
                let mut mac = Hmac::<$hash>::new(key);
                mac.update(message);
                Some(mac.verify(&tag.try_into().ok()?).is_ok())
            },
        )
    };
}

fn run(name: &str, json: &str, (mac, verify): (Mac, Verify)) {
    let file: TestFile<Group, Case> = load(json);
    let mut summary = Summary::new(name, &file);
    for group in &file.test_groups {
        for case in &group.tests {
            let c = &case.case;
            let mut tag = vec![0u8; group.group.tag_size / 8];
            mac(&c.key, &c.msg, &mut tag);
            let mut ok = case.result.matches(Some(&tag), &c.tag);
            if let Some(accepted) = verify(&c.key, &c.msg, &c.tag) {
                ok &= case.result.accepts(accepted);
            }
            summary.check(case, ok);
        }
    }
    summary.finish();
}

#[cfg(feature = "hazmat")]
#[test]
fn hmac_sha1() {
    run(
        "hmac_sha1",
        include_str!("vectors/hmac_sha1_test.json"),
        hmac!(Sha1),
    );
}

#[test]
fn hmac_sha256() {
    run(
        "hmac_sha256",
        include_str!("vectors/hmac_sha256_test.json"),
        hmac!(Sha256),
    );
}

#[test]
fn hmac_sha384() {
    run(
        "hmac_sha384",
        include_str!("vectors/hmac_sha384_test.json"),
        hmac!(Sha384),
    );
}

#[test]
fn hmac_sha512() {
    run(
        "hmac_sha512",
        include_str!("vectors/hmac_sha512_test.json"),
        hmac!(Sha512),
    );
}

#[cfg(feature = "hazmat")]
#[test]
fn hmac_sha3_224() {
    run(
        "hmac_sha3_224",
        include_str!("vectors/hmac_sha3_224_test.json"),
        hmac!(Sha3_224),
    );
}

#[test]
fn hmac_sha3_256() {
    run(
        "hmac_sha3_256",
        include_str!("vectors/hmac_sha3_256_test.json"),
        hmac!(Sha3_256),
    );
}

#[test]
fn hmac_sha3_384() {
    run(
        "hmac_sha3_384",
        include_str!("vectors/hmac_sha3_384_test.json"),
        hmac!(Sha3_384),
    );
}

#[test]
fn hmac_sha3_512() {
    run(
        "hmac_sha3_512",
        include_str!("vectors/hmac_sha3_512_test.json"),
        hmac!(Sha3_512),
    );
}
