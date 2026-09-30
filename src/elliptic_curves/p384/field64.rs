use {super::FieldP384Params, crate::elliptic_curves::Montgomery};

pub type FieldP384 = Montgomery<6, FieldP384Params>;
