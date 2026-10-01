use {super::Scalar448Params, crate::elliptic_curves::Montgomery};

pub type Scalar448Inner = Montgomery<7, Scalar448Params>;
