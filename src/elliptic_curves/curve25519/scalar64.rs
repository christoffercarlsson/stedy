use {super::Scalar25519Params, crate::elliptic_curves::Montgomery};

pub type Scalar25519Inner = Montgomery<4, Scalar25519Params>;
