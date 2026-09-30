use {super::FieldP256Params, crate::elliptic_curves::Montgomery};

pub type FieldP256 = Montgomery<4, FieldP256Params>;
