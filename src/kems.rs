mod ml_kem;

pub use ml_kem::{MlKem1024, MlKem512, MlKem768};

#[cfg(feature = "hazmat")]
pub use ml_kem::*;
