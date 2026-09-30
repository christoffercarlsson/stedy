use {super::Scalar25519Params, crate::elliptic_curves::Montgomery};

pub type Scalar25519Inner = Montgomery<8, Scalar25519Params>;
