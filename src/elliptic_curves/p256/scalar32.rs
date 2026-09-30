use {super::ScalarP256Params, crate::elliptic_curves::Montgomery};

pub type ScalarP256Inner = Montgomery<8, ScalarP256Params>;
