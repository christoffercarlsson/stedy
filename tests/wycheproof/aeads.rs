use {
    crate::{load, Summary, TestFile, TestResult},
    serde::Deserialize,
    stedy::aeads::{ChaCha20Poly1305, XChaCha20Poly1305},
};

#[cfg(feature = "aes")]
use stedy::aeads::{Aes128Gcm, Aes256Gcm};

#[cfg(all(feature = "aes", feature = "hazmat"))]
use stedy::aeads::{Aegis128LTag128, Aegis256Tag128};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Group {
    iv_size: usize,
    key_size: usize,
    tag_size: usize,
}

#[derive(Deserialize)]
struct Case {
    #[serde(deserialize_with = "crate::hex")]
    key: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    iv: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    aad: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    msg: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    ct: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    tag: Vec<u8>,
}

type Encrypt = fn(&[u8], &[u8], &[u8], &mut [u8]) -> Option<[u8; 16]>;
type Decrypt = fn(&[u8], &[u8], &[u8], &mut [u8], &[u8]) -> Option<bool>;

macro_rules! aead {
    ($aead:ty) => {
        (
            |key: &[u8], nonce: &[u8], aad: &[u8], message: &mut [u8]| {
                Some(<$aead>::encrypt(
                    &key.try_into().ok()?,
                    &nonce.try_into().ok()?,
                    Some(aad),
                    message,
                ))
            },
            |key: &[u8], nonce: &[u8], aad: &[u8], message: &mut [u8], tag: &[u8]| {
                Some(<$aead>::decrypt(
                    &key.try_into().ok()?,
                    &nonce.try_into().ok()?,
                    Some(aad),
                    message,
                    &tag.try_into().ok()?,
                ))
            },
        )
    };
}

fn run(
    name: &str,
    json: &str,
    nonce_size: usize,
    key_size: usize,
    (encrypt, decrypt): (Encrypt, Decrypt),
) {
    let file: TestFile<Group, Case> = load(json);
    let mut summary = Summary::new(name, &file);
    for group in &file.test_groups {
        let supported = group.group.iv_size == nonce_size
            && group.group.key_size == key_size
            && group.group.tag_size == 128;
        for case in &group.tests {
            if !supported {
                summary.skip();
                continue;
            }
            let c = &case.case;
            let mut buffer = c.msg.clone();
            let encrypted = encrypt(&c.key, &c.iv, &c.aad, &mut buffer)
                .map(|tag| buffer == c.ct && tag[..] == c.tag[..]);
            let mut buffer = c.ct.clone();
            let decrypted = decrypt(&c.key, &c.iv, &c.aad, &mut buffer, &c.tag)
                .map(|accepted| accepted && buffer == c.msg);
            let ok = match case.result {
                TestResult::Valid => encrypted == Some(true) && decrypted == Some(true),
                TestResult::Invalid => decrypted != Some(true),
                TestResult::Acceptable => true,
            };
            summary.check(case, ok);
        }
    }
    summary.finish();
}

#[test]
fn chacha20poly1305() {
    run(
        "chacha20_poly1305",
        include_str!("vectors/chacha20_poly1305_test.json"),
        96,
        256,
        aead!(ChaCha20Poly1305),
    );
}

#[test]
fn xchacha20poly1305() {
    run(
        "xchacha20_poly1305",
        include_str!("vectors/xchacha20_poly1305_test.json"),
        192,
        256,
        aead!(XChaCha20Poly1305),
    );
}

#[cfg(feature = "aes")]
#[test]
fn aes_gcm() {
    if !Aes128Gcm::is_supported() {
        println!("aes_gcm: skipped, AES is not supported on this CPU");
        return;
    }
    let json = include_str!("vectors/aes_gcm_test.json");
    run("aes_gcm (AES-128)", json, 96, 128, aead!(Aes128Gcm));
    run("aes_gcm (AES-256)", json, 96, 256, aead!(Aes256Gcm));
}

#[cfg(all(feature = "aes", feature = "hazmat"))]
#[test]
fn aegis() {
    if !Aegis128LTag128::is_supported() {
        println!("aegis: skipped, AES is not supported on this CPU");
        return;
    }
    run(
        "aegis128L",
        include_str!("vectors/aegis128L_test.json"),
        128,
        128,
        aead!(Aegis128LTag128),
    );
    run(
        "aegis256",
        include_str!("vectors/aegis256_test.json"),
        256,
        256,
        aead!(Aegis256Tag128),
    );
}
