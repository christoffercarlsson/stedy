use core::fmt::{self, Display, Formatter};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Misuse = 1,
    Decryption = 2,
    LimitExceeded = 3,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Misuse => "misuse",
            Self::Decryption => "decryption failed",
            Self::LimitExceeded => "limit exceeded",
        })
    }
}

impl core::error::Error for Error {}
