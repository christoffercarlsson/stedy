use {super::ScalarP384Params, crate::elliptic_curves::Montgomery};

pub type ScalarP384Inner = Montgomery<12, ScalarP384Params>;
