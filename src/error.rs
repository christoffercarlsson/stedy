use core::fmt::{self, Display, Formatter};

#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Decryption = 1,
    Encoding = 2,
    Entropy = 3,
    InvalidKey = 4,
    LimitExceeded = 5,
    Misuse = 6,
    Verification = 7,
    Unknown = 255,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Decryption => "decryption failed",
            Self::Encoding => "invalid encoding",
            Self::Entropy => "entropy source failed",
            Self::InvalidKey => "invalid key",
            Self::LimitExceeded => "limit exceeded",
            Self::Misuse => "misuse",
            Self::Verification => "verification failed",
            Self::Unknown => "unknown error",
        })
    }
}

impl TryFrom<u8> for Error {
    type Error = Self;

    fn try_from(code: u8) -> Result<Self, Self> {
        match code {
            0 => Err(Self::Misuse),
            1 => Ok(Self::Decryption),
            2 => Ok(Self::Encoding),
            3 => Ok(Self::Entropy),
            4 => Ok(Self::InvalidKey),
            5 => Ok(Self::LimitExceeded),
            6 => Ok(Self::Misuse),
            7 => Ok(Self::Verification),
            _ => Ok(Self::Unknown),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_from_u8() {
        let errors = [
            Error::Decryption,
            Error::Encoding,
            Error::Entropy,
            Error::InvalidKey,
            Error::LimitExceeded,
            Error::Misuse,
            Error::Verification,
        ];
        for error in errors {
            assert_eq!(Error::try_from(error as u8), Ok(error));
        }
        assert_eq!(Error::try_from(0), Err(Error::Misuse));
        assert_eq!(Error::try_from(8), Ok(Error::Unknown));
    }
}
