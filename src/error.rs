use core::fmt::{self, Display, Formatter};

#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Misuse = 1,
    Decryption = 2,
    LimitExceeded = 3,
    InvalidKey = 4,
    Encoding = 5,
    Verification = 6,
    Entropy = 7,
    Unknown = 255,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Misuse => "misuse",
            Self::Decryption => "decryption failed",
            Self::LimitExceeded => "limit exceeded",
            Self::InvalidKey => "invalid key",
            Self::Encoding => "invalid encoding",
            Self::Verification => "verification failed",
            Self::Entropy => "entropy source failed",
            Self::Unknown => "unknown error",
        })
    }
}

impl TryFrom<u8> for Error {
    type Error = Self;

    fn try_from(code: u8) -> Result<Self, Self> {
        match code {
            0 => Err(Self::Misuse),
            1 => Ok(Self::Misuse),
            2 => Ok(Self::Decryption),
            3 => Ok(Self::LimitExceeded),
            4 => Ok(Self::InvalidKey),
            5 => Ok(Self::Encoding),
            6 => Ok(Self::Verification),
            7 => Ok(Self::Entropy),
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
            Error::Misuse,
            Error::Decryption,
            Error::LimitExceeded,
            Error::InvalidKey,
            Error::Encoding,
            Error::Verification,
            Error::Entropy,
        ];
        for error in errors {
            assert_eq!(Error::try_from(error as u8), Ok(error));
        }
        assert_eq!(Error::try_from(0), Err(Error::Misuse));
        assert_eq!(Error::try_from(8), Ok(Error::Unknown));
    }
}
