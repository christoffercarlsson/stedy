use {super::ScalarP521Params, crate::elliptic_curves::Montgomery};

pub type ScalarP521Inner = Montgomery<18, ScalarP521Params>;
