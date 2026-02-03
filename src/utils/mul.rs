#[cfg_attr(target_pointer_width = "32", path = "mul/mul32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "mul/mul64.rs")]
mod multiply;

pub use multiply::*;
