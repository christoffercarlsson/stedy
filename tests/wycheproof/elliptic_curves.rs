use {
    crate::{NoGroup, Summary, TestFile, load},
    serde::Deserialize,
    stedy::elliptic_curves::Ristretto255,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    #[serde(deserialize_with = "crate::hex")]
    scalar: Vec<u8>,
    #[serde(default, deserialize_with = "crate::hex_opt")]
    result_scalar: Option<Vec<u8>>,
}

#[test]
fn ristretto255_scalar_invert() {
    let file: TestFile<NoGroup, Case> =
        load(include_str!("vectors/ristretto255_scalar_invert_test.json"));
    let mut summary = Summary::new("ristretto255_scalar_invert", &file);
    for group in &file.test_groups {
        for case in &group.tests {
            let c = &case.case;
            let inverse = <&[u8; 32]>::try_from(c.scalar.as_slice())
                .ok()
                .and_then(|scalar| Ristretto255::scalar_invert(scalar).ok());
            let expected = c.result_scalar.as_deref().unwrap_or_default();
            summary.check(
                case,
                case.result
                    .matches(inverse.as_deref().map(<[u8; 32]>::as_slice), expected),
            );
        }
    }
    summary.finish();
}
