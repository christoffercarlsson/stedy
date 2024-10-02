use core::mem::size_of;

use crate::{Error, CHACHA20_POLY1305_NONCE_SIZE, XCHACHA20_POLY1305_NONCE_SIZE};

fn read_byte_offset<const N: usize>(src: &[u8], offset: usize) -> Result<[u8; N], Error> {
    src.get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(Error::InvalidOffset)
}

pub fn read_u8(src: &[u8], offset: usize) -> Result<u8, Error> {
    let bytes = read_byte_offset::<{ size_of::<u8>() }>(src, offset)?;
    Ok(u8::from_be_bytes(bytes))
}

fn read_u16(src: &[u8], offset: usize, little_endian: bool) -> Result<u16, Error> {
    let bytes = read_byte_offset::<{ size_of::<u16>() }>(src, offset)?;
    Ok(if little_endian {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

pub fn read_u16_be(src: &[u8], offset: usize) -> Result<u16, Error> {
    read_u16(src, offset, false)
}

pub fn read_u16_le(src: &[u8], offset: usize) -> Result<u16, Error> {
    read_u16(src, offset, true)
}

fn read_u32(src: &[u8], offset: usize, little_endian: bool) -> Result<u32, Error> {
    let bytes = read_byte_offset::<{ size_of::<u32>() }>(src, offset)?;
    Ok(if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

pub fn read_u32_be(src: &[u8], offset: usize) -> Result<u32, Error> {
    read_u32(src, offset, false)
}

pub fn read_u32_le(src: &[u8], offset: usize) -> Result<u32, Error> {
    read_u32(src, offset, true)
}

fn read_u64(src: &[u8], offset: usize, little_endian: bool) -> Result<u64, Error> {
    let bytes = read_byte_offset::<{ size_of::<u64>() }>(src, offset)?;
    Ok(if little_endian {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

pub fn read_u64_be(src: &[u8], offset: usize) -> Result<u64, Error> {
    read_u64(src, offset, false)
}

pub fn read_u64_le(src: &[u8], offset: usize) -> Result<u64, Error> {
    read_u64(src, offset, true)
}

fn read_u128(src: &[u8], offset: usize, little_endian: bool) -> Result<u128, Error> {
    let bytes = read_byte_offset::<{ size_of::<u128>() }>(src, offset)?;
    Ok(if little_endian {
        u128::from_le_bytes(bytes)
    } else {
        u128::from_be_bytes(bytes)
    })
}

pub fn read_u128_be(src: &[u8], offset: usize) -> Result<u128, Error> {
    read_u128(src, offset, false)
}

pub fn read_u128_le(src: &[u8], offset: usize) -> Result<u128, Error> {
    read_u128(src, offset, true)
}

fn read_usize(src: &[u8], offset: usize, little_endian: bool) -> Result<usize, Error> {
    let bytes = read_byte_offset::<{ size_of::<usize>() }>(src, offset)?;
    Ok(if little_endian {
        usize::from_le_bytes(bytes)
    } else {
        usize::from_be_bytes(bytes)
    })
}

pub fn read_usize_be(src: &[u8], offset: usize) -> Result<usize, Error> {
    read_usize(src, offset, false)
}

pub fn read_usize_le(src: &[u8], offset: usize) -> Result<usize, Error> {
    read_usize(src, offset, true)
}

pub fn read_i8(src: &[u8], offset: usize) -> Result<i8, Error> {
    let bytes = read_byte_offset::<{ size_of::<i8>() }>(src, offset)?;
    Ok(i8::from_be_bytes(bytes))
}

fn read_i16(src: &[u8], offset: usize, little_endian: bool) -> Result<i16, Error> {
    let bytes = read_byte_offset::<{ size_of::<i16>() }>(src, offset)?;
    Ok(if little_endian {
        i16::from_le_bytes(bytes)
    } else {
        i16::from_be_bytes(bytes)
    })
}

pub fn read_i16_be(src: &[u8], offset: usize) -> Result<i16, Error> {
    read_i16(src, offset, false)
}

pub fn read_i16_le(src: &[u8], offset: usize) -> Result<i16, Error> {
    read_i16(src, offset, true)
}

fn read_i32(src: &[u8], offset: usize, little_endian: bool) -> Result<i32, Error> {
    let bytes = read_byte_offset::<{ size_of::<i32>() }>(src, offset)?;
    Ok(if little_endian {
        i32::from_le_bytes(bytes)
    } else {
        i32::from_be_bytes(bytes)
    })
}

pub fn read_i32_be(src: &[u8], offset: usize) -> Result<i32, Error> {
    read_i32(src, offset, false)
}

pub fn read_i32_le(src: &[u8], offset: usize) -> Result<i32, Error> {
    read_i32(src, offset, true)
}

fn read_i64(src: &[u8], offset: usize, little_endian: bool) -> Result<i64, Error> {
    let bytes = read_byte_offset::<{ size_of::<i64>() }>(src, offset)?;
    Ok(if little_endian {
        i64::from_le_bytes(bytes)
    } else {
        i64::from_be_bytes(bytes)
    })
}

pub fn read_i64_be(src: &[u8], offset: usize) -> Result<i64, Error> {
    read_i64(src, offset, false)
}

pub fn read_i64_le(src: &[u8], offset: usize) -> Result<i64, Error> {
    read_i64(src, offset, true)
}

fn read_i128(src: &[u8], offset: usize, little_endian: bool) -> Result<i128, Error> {
    let bytes = read_byte_offset::<{ size_of::<i128>() }>(src, offset)?;
    Ok(if little_endian {
        i128::from_le_bytes(bytes)
    } else {
        i128::from_be_bytes(bytes)
    })
}

pub fn read_i128_be(src: &[u8], offset: usize) -> Result<i128, Error> {
    read_i128(src, offset, false)
}

pub fn read_i128_le(src: &[u8], offset: usize) -> Result<i128, Error> {
    read_i128(src, offset, true)
}

fn read_isize(src: &[u8], offset: usize, little_endian: bool) -> Result<isize, Error> {
    let bytes = read_byte_offset::<{ size_of::<isize>() }>(src, offset)?;
    Ok(if little_endian {
        isize::from_le_bytes(bytes)
    } else {
        isize::from_be_bytes(bytes)
    })
}

pub fn read_isize_be(src: &[u8], offset: usize) -> Result<isize, Error> {
    read_isize(src, offset, false)
}

pub fn read_isize_le(src: &[u8], offset: usize) -> Result<isize, Error> {
    read_isize(src, offset, true)
}

fn read_f32(src: &[u8], offset: usize, little_endian: bool) -> Result<f32, Error> {
    let bytes = read_byte_offset::<{ size_of::<f32>() }>(src, offset)?;
    Ok(if little_endian {
        f32::from_le_bytes(bytes)
    } else {
        f32::from_be_bytes(bytes)
    })
}

pub fn read_f32_be(src: &[u8], offset: usize) -> Result<f32, Error> {
    read_f32(src, offset, false)
}

pub fn read_f32_le(src: &[u8], offset: usize) -> Result<f32, Error> {
    read_f32(src, offset, true)
}

fn read_f64(src: &[u8], offset: usize, little_endian: bool) -> Result<f64, Error> {
    let bytes = read_byte_offset::<{ size_of::<f64>() }>(src, offset)?;
    Ok(if little_endian {
        f64::from_le_bytes(bytes)
    } else {
        f64::from_be_bytes(bytes)
    })
}

pub fn read_f64_be(src: &[u8], offset: usize) -> Result<f64, Error> {
    read_f64(src, offset, false)
}

pub fn read_f64_le(src: &[u8], offset: usize) -> Result<f64, Error> {
    read_f64(src, offset, true)
}

fn write_byte_offset(dest: &mut [u8], offset: usize, bytes: &[u8]) -> Result<(), Error> {
    if dest.len() < (bytes.len() + offset) {
        return Err(Error::InvalidOffset);
    }
    dest[offset..offset + bytes.len()].copy_from_slice(bytes);
    Ok(())
}

pub fn write_u8(dest: &mut [u8], offset: usize, value: u8) -> Result<(), Error> {
    write_byte_offset(dest, offset, &[value])
}

fn write_u16(dest: &mut [u8], offset: usize, little_endian: bool, value: u16) -> Result<(), Error> {
    let bytes = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    write_byte_offset(dest, offset, &bytes)
}

pub fn write_u16_be(dest: &mut [u8], offset: usize, value: u16) -> Result<(), Error> {
    write_u16(dest, offset, false, value)
}

pub fn write_u16_le(dest: &mut [u8], offset: usize, value: u16) -> Result<(), Error> {
    write_u16(dest, offset, true, value)
}

fn write_u32(dest: &mut [u8], offset: usize, little_endian: bool, value: u32) -> Result<(), Error> {
    let bytes = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    write_byte_offset(dest, offset, &bytes)
}

pub fn write_u32_be(dest: &mut [u8], offset: usize, value: u32) -> Result<(), Error> {
    write_u32(dest, offset, false, value)
}

pub fn write_u32_le(dest: &mut [u8], offset: usize, value: u32) -> Result<(), Error> {
    write_u32(dest, offset, true, value)
}

fn write_u64(dest: &mut [u8], offset: usize, little_endian: bool, value: u64) -> Result<(), Error> {
    let bytes = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    write_byte_offset(dest, offset, &bytes)
}

pub fn write_u64_be(dest: &mut [u8], offset: usize, value: u64) -> Result<(), Error> {
    write_u64(dest, offset, false, value)
}

pub fn write_u64_le(dest: &mut [u8], offset: usize, value: u64) -> Result<(), Error> {
    write_u64(dest, offset, true, value)
}

fn write_u128(
    dest: &mut [u8],
    offset: usize,
    little_endian: bool,
    value: u128,
) -> Result<(), Error> {
    let bytes = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    write_byte_offset(dest, offset, &bytes)
}

pub fn write_u128_be(dest: &mut [u8], offset: usize, value: u128) -> Result<(), Error> {
    write_u128(dest, offset, false, value)
}

pub fn write_u128_le(dest: &mut [u8], offset: usize, value: u128) -> Result<(), Error> {
    write_u128(dest, offset, true, value)
}

fn write_usize(
    dest: &mut [u8],
    offset: usize,
    little_endian: bool,
    value: usize,
) -> Result<(), Error> {
    let bytes = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    write_byte_offset(dest, offset, &bytes)
}

pub fn write_usize_be(dest: &mut [u8], offset: usize, value: usize) -> Result<(), Error> {
    write_usize(dest, offset, false, value)
}

pub fn write_usize_le(dest: &mut [u8], offset: usize, value: usize) -> Result<(), Error> {
    write_usize(dest, offset, true, value)
}

pub fn write_i8(dest: &mut [u8], offset: usize, value: i8) -> Result<(), Error> {
    let bytes = value.to_be_bytes();
    write_byte_offset(dest, offset, &bytes)
}

fn write_i16(dest: &mut [u8], offset: usize, little_endian: bool, value: i16) -> Result<(), Error> {
    let bytes = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    write_byte_offset(dest, offset, &bytes)
}

pub fn write_i16_be(dest: &mut [u8], offset: usize, value: i16) -> Result<(), Error> {
    write_i16(dest, offset, false, value)
}

pub fn write_i16_le(dest: &mut [u8], offset: usize, value: i16) -> Result<(), Error> {
    write_i16(dest, offset, true, value)
}

fn write_i32(dest: &mut [u8], offset: usize, little_endian: bool, value: i32) -> Result<(), Error> {
    let bytes = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    write_byte_offset(dest, offset, &bytes)
}

pub fn write_i32_be(dest: &mut [u8], offset: usize, value: i32) -> Result<(), Error> {
    write_i32(dest, offset, false, value)
}

pub fn write_i32_le(dest: &mut [u8], offset: usize, value: i32) -> Result<(), Error> {
    write_i32(dest, offset, true, value)
}

fn write_i64(dest: &mut [u8], offset: usize, little_endian: bool, value: i64) -> Result<(), Error> {
    let bytes = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    write_byte_offset(dest, offset, &bytes)
}

pub fn write_i64_be(dest: &mut [u8], offset: usize, value: i64) -> Result<(), Error> {
    write_i64(dest, offset, false, value)
}

pub fn write_i64_le(dest: &mut [u8], offset: usize, value: i64) -> Result<(), Error> {
    write_i64(dest, offset, true, value)
}

fn write_i128(
    dest: &mut [u8],
    offset: usize,
    little_endian: bool,
    value: i128,
) -> Result<(), Error> {
    let bytes = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    write_byte_offset(dest, offset, &bytes)
}

pub fn write_i128_be(dest: &mut [u8], offset: usize, value: i128) -> Result<(), Error> {
    write_i128(dest, offset, false, value)
}

pub fn write_i128_le(dest: &mut [u8], offset: usize, value: i128) -> Result<(), Error> {
    write_i128(dest, offset, true, value)
}

fn write_isize(
    dest: &mut [u8],
    offset: usize,
    little_endian: bool,
    value: isize,
) -> Result<(), Error> {
    let bytes = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    write_byte_offset(dest, offset, &bytes)
}

pub fn write_isize_be(dest: &mut [u8], offset: usize, value: isize) -> Result<(), Error> {
    write_isize(dest, offset, false, value)
}

pub fn write_isize_le(dest: &mut [u8], offset: usize, value: isize) -> Result<(), Error> {
    write_isize(dest, offset, true, value)
}

fn write_f32(dest: &mut [u8], offset: usize, little_endian: bool, value: f32) -> Result<(), Error> {
    let bytes = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    write_byte_offset(dest, offset, &bytes)
}

pub fn write_f32_be(dest: &mut [u8], offset: usize, value: f32) -> Result<(), Error> {
    write_f32(dest, offset, false, value)
}

pub fn write_f32_le(dest: &mut [u8], offset: usize, value: f32) -> Result<(), Error> {
    write_f32(dest, offset, true, value)
}

fn write_f64(dest: &mut [u8], offset: usize, little_endian: bool, value: f64) -> Result<(), Error> {
    let bytes = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    write_byte_offset(dest, offset, &bytes)
}

pub fn write_f64_be(dest: &mut [u8], offset: usize, value: f64) -> Result<(), Error> {
    write_f64(dest, offset, false, value)
}

pub fn write_f64_le(dest: &mut [u8], offset: usize, value: f64) -> Result<(), Error> {
    write_f64(dest, offset, true, value)
}

pub fn read_nonce(nonce: &[u8]) -> Result<u64, Error> {
    let size = nonce.len();
    if size != CHACHA20_POLY1305_NONCE_SIZE && size != XCHACHA20_POLY1305_NONCE_SIZE {
        return Err(Error::InvalidNonce);
    }
    read_u64_be(nonce, size - size_of::<u64>())
}

pub fn increment_nonce(nonce: &mut [u8]) -> Result<(), Error> {
    let value = read_nonce(nonce)?;
    if value == u64::MAX {
        return Err(Error::IncrementFailed);
    }
    write_u64_be(nonce, nonce.len() - size_of::<u64>(), value + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u8() {
        let mut bytes: [u8; 2] = [0; 2];
        let value = 127;
        write_u8(&mut bytes, 1, value).unwrap();
        assert_eq!(read_u8(&bytes, 1).unwrap(), value);
    }

    #[test]
    fn test_u16() {
        let mut bytes: [u8; 2] = [0; 2];
        let value = 32767;
        write_u16_be(&mut bytes, 0, value).unwrap();
        assert_eq!(read_u16_be(&bytes, 0).unwrap(), value);
        write_u16_le(&mut bytes, 0, value).unwrap();
        assert_eq!(read_u16_le(&bytes, 0).unwrap(), value);
    }

    #[test]
    fn test_u32() {
        let mut bytes: [u8; 4] = [0; 4];
        let value = 4294967295;
        write_u32_be(&mut bytes, 0, value).unwrap();
        assert_eq!(read_u32_be(&bytes, 0).unwrap(), value);
        write_u32_le(&mut bytes, 0, value).unwrap();
        assert_eq!(read_u32_le(&bytes, 0).unwrap(), value);
    }

    #[test]
    fn test_u64() {
        let mut bytes: [u8; 8] = [0; 8];
        let value = 18446744073709551615;
        write_u64_be(&mut bytes, 0, value).unwrap();
        assert_eq!(read_u64_be(&bytes, 0).unwrap(), value);
        write_u64_le(&mut bytes, 0, value).unwrap();
        assert_eq!(read_u64_le(&bytes, 0).unwrap(), value);
    }

    #[test]
    fn test_u128() {
        let mut bytes: [u8; 16] = [0; 16];
        let value = 13832977027068018235629712760601812484;
        write_u128_be(&mut bytes, 0, value).unwrap();
        assert_eq!(read_u128_be(&bytes, 0).unwrap(), value);
        write_u128_le(&mut bytes, 0, value).unwrap();
        assert_eq!(read_u128_le(&bytes, 0).unwrap(), value);
    }

    #[test]
    fn test_usize() {
        let mut bytes: [u8; 8] = [0; 8];
        let value = 18446744073709551615;
        write_usize_be(&mut bytes, 0, value).unwrap();
        assert_eq!(read_usize_be(&bytes, 0).unwrap(), value);
        write_usize_le(&mut bytes, 0, value).unwrap();
        assert_eq!(read_usize_le(&bytes, 0).unwrap(), value);
    }

    #[test]
    fn test_i8() {
        let mut bytes: [u8; 2] = [0; 2];
        let value = -127;
        write_i8(&mut bytes, 1, value).unwrap();
        assert_eq!(read_i8(&bytes, 1).unwrap(), value);
    }

    #[test]
    fn test_i16() {
        let mut bytes: [u8; 2] = [0; 2];
        let value = -25084;
        write_i16_be(&mut bytes, 0, value).unwrap();
        assert_eq!(read_i16_be(&bytes, 0).unwrap(), value);
        write_i16_le(&mut bytes, 0, value).unwrap();
        assert_eq!(read_i16_le(&bytes, 0).unwrap(), value);
    }

    #[test]
    fn test_i32() {
        let mut bytes: [u8; 4] = [0; 4];
        let value = -1643898624;
        write_i32_be(&mut bytes, 0, value).unwrap();
        assert_eq!(read_i32_be(&bytes, 0).unwrap(), value);
        write_i32_le(&mut bytes, 0, value).unwrap();
        assert_eq!(read_i32_le(&bytes, 0).unwrap(), value);
    }

    #[test]
    fn test_i64() {
        let mut bytes: [u8; 8] = [0; 8];
        let value = 749887187234460992;
        write_i64_be(&mut bytes, 0, value).unwrap();
        assert_eq!(read_i64_be(&bytes, 0).unwrap(), value);
        write_i64_le(&mut bytes, 0, value).unwrap();
        assert_eq!(read_i64_le(&bytes, 0).unwrap(), value);
    }

    #[test]
    fn test_i128() {
        let mut bytes: [u8; 16] = [0; 16];
        let value = 6138576013918730160740991568590301194;
        write_i128_be(&mut bytes, 0, value).unwrap();
        assert_eq!(read_i128_be(&bytes, 0).unwrap(), value);
        write_i128_le(&mut bytes, 0, value).unwrap();
        assert_eq!(read_i128_le(&bytes, 0).unwrap(), value);
    }

    #[test]
    fn test_isize() {
        let mut bytes: [u8; 8] = [0; 8];
        let value = 749887187234460992;
        write_isize_be(&mut bytes, 0, value).unwrap();
        assert_eq!(read_isize_be(&bytes, 0).unwrap(), value);
        write_isize_le(&mut bytes, 0, value).unwrap();
        assert_eq!(read_isize_le(&bytes, 0).unwrap(), value);
    }

    #[test]
    fn test_f32() {
        let mut bytes: [u8; 4] = [0; 4];
        let value = 1.2345;
        write_f32_be(&mut bytes, 0, value).unwrap();
        assert_eq!(read_f32_be(&bytes, 0).unwrap(), value);
        write_f32_le(&mut bytes, 0, value).unwrap();
        assert_eq!(read_f32_le(&bytes, 0).unwrap(), value);
    }

    #[test]
    fn test_f64() {
        let mut bytes: [u8; 8] = [0; 8];
        let value = 5.4321;
        write_f64_be(&mut bytes, 0, value).unwrap();
        assert_eq!(read_f64_be(&bytes, 0).unwrap(), value);
        write_f64_le(&mut bytes, 0, value).unwrap();
        assert_eq!(read_f64_le(&bytes, 0).unwrap(), value);
    }

    #[test]
    fn test_increment_nonce() {
        let mut n1 = [0; CHACHA20_POLY1305_NONCE_SIZE];
        increment_nonce(&mut n1).unwrap();
        assert_eq!(n1, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let mut n2 = [0; XCHACHA20_POLY1305_NONCE_SIZE];
        increment_nonce(&mut n2).unwrap();
        assert_eq!(
            n2,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
    }
}
