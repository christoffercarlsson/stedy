use {super::FieldP384Params, crate::elliptic_curves::Montgomery};

pub type FieldP384 = Montgomery<12, FieldP384Params>;
