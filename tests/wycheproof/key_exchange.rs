use {
    crate::{compress_point, load, pad_scalar, NoGroup, Summary, TestFile, TestResult},
    serde::Deserialize,
    stedy::key_exchange::{P256, P384, P521, X25519, X448},
};

#[derive(Deserialize)]
struct Case {
    #[serde(deserialize_with = "crate::hex")]
    public: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    private: Vec<u8>,
    #[serde(deserialize_with = "crate::hex")]
    shared: Vec<u8>,
}

type Exchange = fn(&[u8], &[u8]) -> Option<Vec<u8>>;

macro_rules! ecdh {
    ($ecdh:ty, $scalar:literal, $point:literal) => {
        |private_key: &[u8], public_key: &[u8]| {
            let private_key = pad_scalar::<$scalar>(private_key)?;
            let public_key = compress_point::<$point>(public_key)?;
            Some(<$ecdh>::key_exchange(&private_key, &public_key)?.to_vec())
        }
    };
}

macro_rules! xdh {
    ($xdh:ty) => {
        |private_key: &[u8], public_key: &[u8]| {
            let private_key = private_key.try_into().ok()?;
            let public_key = public_key.try_into().ok()?;
            Some(<$xdh>::key_exchange(&private_key, &public_key)?.to_vec())
        }
    };
}

fn run_ecdh(name: &str, json: &str, exchange: Exchange) {
    let file: TestFile<NoGroup, Case> = load(json);
    let mut summary = Summary::new(name, &file);
    for group in &file.test_groups {
        for case in &group.tests {
            let c = &case.case;
            let shared = exchange(&c.private, &c.public);
            let ok = match case.result {
                TestResult::Valid | TestResult::Acceptable => {
                    shared.as_deref() == Some(&c.shared[..])
                }
                TestResult::Invalid => shared.as_deref() != Some(&c.shared[..]),
            };
            summary.check(case, ok);
        }
    }
    summary.finish();
}

fn run_xdh(name: &str, json: &str, exchange: Exchange) {
    let file: TestFile<NoGroup, Case> = load(json);
    let mut summary = Summary::new(name, &file);
    for group in &file.test_groups {
        for case in &group.tests {
            let c = &case.case;
            let shared = exchange(&c.private, &c.public);
            let ok = match (case.result, shared.as_deref()) {
                (TestResult::Valid | TestResult::Acceptable, Some(shared)) => shared == c.shared,
                (TestResult::Valid, None) => false,
                (TestResult::Invalid, None) => true,
                (TestResult::Invalid, Some(shared)) => shared != c.shared,
                (TestResult::Acceptable, None) => case.has_flag("ZeroSharedSecret"),
            };
            summary.check(case, ok);
        }
    }
    summary.finish();
}

#[test]
fn x25519() {
    run_xdh(
        "x25519",
        include_str!("vectors/x25519_test.json"),
        xdh!(X25519),
    );
}

#[test]
fn x448() {
    run_xdh("x448", include_str!("vectors/x448_test.json"), xdh!(X448));
}

#[test]
fn ecdh_p256() {
    run_ecdh(
        "ecdh_secp256r1_ecpoint",
        include_str!("vectors/ecdh_secp256r1_ecpoint_test.json"),
        ecdh!(P256, 32, 33),
    );
}

#[test]
fn ecdh_p384() {
    run_ecdh(
        "ecdh_secp384r1_ecpoint",
        include_str!("vectors/ecdh_secp384r1_ecpoint_test.json"),
        ecdh!(P384, 48, 49),
    );
}

#[test]
fn ecdh_p521() {
    run_ecdh(
        "ecdh_secp521r1_ecpoint",
        include_str!("vectors/ecdh_secp521r1_ecpoint_test.json"),
        ecdh!(P521, 66, 67),
    );
}
