mod aeads;
mod kdfs;
mod kems;
mod key_exchange;
mod macs;
mod signatures;

use {
    serde::{de::DeserializeOwned, Deserialize, Deserializer},
    stedy::encoding::{decode, Encoding},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestFile<G, C> {
    pub number_of_tests: usize,
    pub test_groups: Vec<TestGroup<G, C>>,
}

#[derive(Deserialize)]
pub struct TestGroup<G, C> {
    #[serde(flatten)]
    pub group: G,
    pub tests: Vec<TestCase<C>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestCase<C> {
    pub tc_id: usize,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub flags: Vec<String>,
    pub result: TestResult,
    #[serde(flatten)]
    pub case: C,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TestResult {
    Valid,
    Invalid,
    Acceptable,
}

#[derive(Deserialize)]
pub struct NoGroup {}

pub struct Summary {
    name: String,
    total: usize,
    run: usize,
    skipped: usize,
    failures: Vec<String>,
}

impl<C> TestCase<C> {
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f == flag)
    }
}

impl TestResult {
    pub fn accepts(self, accepted: bool) -> bool {
        match self {
            Self::Valid => accepted,
            Self::Invalid => !accepted,
            Self::Acceptable => true,
        }
    }

    pub fn matches(self, output: Option<&[u8]>, expected: &[u8]) -> bool {
        match self {
            Self::Valid => output == Some(expected),
            Self::Invalid => output != Some(expected),
            Self::Acceptable => output.is_none_or(|output| output == expected),
        }
    }
}

impl Summary {
    pub fn new<G, C>(name: &str, file: &TestFile<G, C>) -> Self {
        Self {
            name: name.to_string(),
            total: file.number_of_tests,
            run: 0,
            skipped: 0,
            failures: Vec::new(),
        }
    }

    pub fn skip(&mut self) {
        self.skipped += 1;
    }

    pub fn check<C>(&mut self, case: &TestCase<C>, ok: bool) {
        self.run += 1;
        if !ok {
            self.failures.push(format!(
                "tcId {} ({:?}, {:?}): {}",
                case.tc_id, case.result, case.flags, case.comment
            ));
        }
    }

    pub fn finish(self) {
        assert_eq!(
            self.run + self.skipped,
            self.total,
            "{}: every case must be run or skipped",
            self.name
        );
        assert!(self.run > 0, "{}: no cases run", self.name);
        println!("{}: {} run, {} skipped", self.name, self.run, self.skipped);
        assert!(
            self.failures.is_empty(),
            "{}: {} failures\n{}",
            self.name,
            self.failures.len(),
            self.failures.join("\n")
        );
    }
}

pub fn load<G: DeserializeOwned, C: DeserializeOwned>(json: &str) -> TestFile<G, C> {
    serde_json::from_str(json).expect("Wycheproof test file parses")
}

pub fn hex<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let encoded = String::deserialize(deserializer)?;
    let mut decoded = vec![0u8; encoded.len() / 2];
    let size = decode(Encoding::Base16, encoded.as_bytes(), &mut decoded)
        .ok_or_else(|| serde::de::Error::custom("invalid hex"))?
        .len();
    decoded.truncate(size);
    Ok(decoded)
}

pub fn hex_opt<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error> {
    #[derive(Deserialize)]
    struct Hex(#[serde(deserialize_with = "hex")] Vec<u8>);
    Ok(Option::<Hex>::deserialize(deserializer)?.map(|hex| hex.0))
}

pub fn compress_point<const N: usize>(point: &[u8]) -> Option<[u8; N]> {
    let mut compressed = [0u8; N];
    match point.split_first()? {
        (0x04, coordinates) if coordinates.len() == 2 * (N - 1) => {
            let (x, y) = coordinates.split_at(N - 1);
            compressed[0] = 0x02 | (y[N - 2] & 1);
            compressed[1..].copy_from_slice(x);
            Some(compressed)
        }
        (0x02 | 0x03, _) if point.len() == N => {
            compressed.copy_from_slice(point);
            Some(compressed)
        }
        _ => None,
    }
}

pub fn pad_scalar<const N: usize>(mut scalar: &[u8]) -> Option<[u8; N]> {
    while scalar.len() > N && scalar[0] == 0 {
        scalar = &scalar[1..];
    }
    if scalar.len() > N {
        return None;
    }
    let mut padded = [0u8; N];
    padded[N - scalar.len()..].copy_from_slice(scalar);
    Some(padded)
}

#[cfg(feature = "hazmat")]
pub struct FixedRng<'a>(pub &'a [u8]);

#[cfg(feature = "hazmat")]
impl stedy::traits::CryptoRng for FixedRng<'_> {
    fn fill(&mut self, bytes: &mut [u8]) {
        let (head, tail) = self.0.split_at(bytes.len());
        bytes.copy_from_slice(head);
        self.0 = tail;
    }
}
