use {
    serde::{Deserialize, Deserializer},
    stedy::{
        encoding::{Encoding, decode},
        signatures::Ed25519,
    },
};

#[derive(Deserialize)]
struct Vector {
    number: usize,
    #[serde(deserialize_with = "hex")]
    key: Vec<u8>,
    #[serde(deserialize_with = "hex")]
    sig: Vec<u8>,
    msg: String,
    #[serde(default, deserialize_with = "flags")]
    flags: Vec<String>,
}

impl Vector {
    fn has_flag(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f == flag)
    }

    // Small order points and non-canonical encodings are rejected outright.
    // The cofactored equation cancels any low order residue, so mixed order
    // points are otherwise accepted.
    fn expected(&self) -> bool {
        !(self.has_flag("low_order_A")
            || self.has_flag("low_order_R")
            || self.has_flag("non_canonical_A")
            || self.has_flag("non_canonical_R"))
    }
}

fn hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let mut decoded = vec![0u8; encoded.len() / 2];
    let size = decode(Encoding::Base16, encoded.as_bytes(), &mut decoded)
        .map_err(|_| serde::de::Error::custom("invalid hex"))?
        .len();
    decoded.truncate(size);
    Ok(decoded)
}

fn flags<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default())
}

// https://github.com/C2SP/CCTV/tree/main/ed25519

#[test]
fn ed25519() {
    let vectors: Vec<Vector> = serde_json::from_str(include_str!("vectors/ed25519vectors.json"))
        .expect("CCTV test file parses");
    assert!(!vectors.is_empty(), "ed25519: no cases run");
    let failures: Vec<String> = vectors
        .iter()
        .filter(|vector| {
            let public_key = vector.key.as_slice().try_into().expect("key is 32 bytes");
            let signature = vector.sig.as_slice().try_into().expect("sig is 64 bytes");
            let accepted = Ed25519::verify(vector.msg.as_bytes(), &public_key, &signature).is_ok();
            accepted != vector.expected()
        })
        .map(|vector| format!("number {} ({:?})", vector.number, vector.flags))
        .collect();
    println!("ed25519: {} run", vectors.len());
    assert!(
        failures.is_empty(),
        "ed25519: {} failures\n{}",
        failures.len(),
        failures.join("\n")
    );
}
