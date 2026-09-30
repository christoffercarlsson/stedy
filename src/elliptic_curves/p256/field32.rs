use {super::FieldP256Params, crate::elliptic_curves::Montgomery};

pub type FieldP256 = Montgomery<8, FieldP256Params>;
