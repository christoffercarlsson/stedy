mod ml_kem;
mod x_wing;

pub use {
    ml_kem::{MlKem, MlKem512, MlKem768, MlKem1024},
    x_wing::{XWing, XWingKem},
};

#[cfg(feature = "hazmat")]
pub use {
    ml_kem::{MlKem512With, MlKem768With, MlKem1024With, MlKemNtt},
    x_wing::XWingWith,
};

#[cfg(not(feature = "hazmat"))]
pub(crate) use ml_kem::MlKemNtt;
