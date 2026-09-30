use {super::ScalarP384Params, crate::elliptic_curves::Montgomery};

pub type ScalarP384Inner = Montgomery<6, ScalarP384Params>;
