use {super::Scalar448Params, crate::elliptic_curves::Montgomery};

pub type Scalar448Inner = Montgomery<14, Scalar448Params>;
