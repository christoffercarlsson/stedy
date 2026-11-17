use crate::{
    Error,
    utils::{Choice, Secret, declassify, wipe},
};

const BASE16_ALPHABET: [Range; 2] = [Range::new(0, b'0', 10), Range::new(10, b'a', 6)];
const BASE32_ALPHABET: [Range; 2] = [Range::new(0, b'A', 26), Range::new(26, b'2', 6)];
const BASE64_ALPHABET: [Range; 5] = [
    Range::new(0, b'A', 26),
    Range::new(26, b'a', 26),
    Range::new(52, b'0', 10),
    Range::new(62, b'+', 1),
    Range::new(63, b'/', 1),
];
const BASE64_ALPHABET_URL: [Range; 5] = [
    Range::new(0, b'A', 26),
    Range::new(26, b'a', 26),
    Range::new(52, b'0', 10),
    Range::new(62, b'-', 1),
    Range::new(63, b'_', 1),
];
const PADDING_BYTE: u8 = 61;

struct Range {
    index: u8,
    character: u8,
    size: u8,
}

impl Range {
    const fn new(index: u8, character: u8, size: u8) -> Self {
        Self {
            index,
            character,
            size,
        }
    }
}

struct Base<const BITS: usize, const GROUPS: usize> {
    alphabet: &'static [Range],
    offset: usize,
}

impl<const BITS: usize, const GROUPS: usize> Base<BITS, GROUPS> {
    const MASK: u32 = (1 << BITS) - 1;

    fn new(alphabet: &'static [Range]) -> Self {
        Self {
            alphabet,
            offset: 0,
        }
    }

    fn encode<'a>(
        mut self,
        padded: bool,
        decoded: &[u8],
        encoded: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        if Self::encoded_size(padded, decoded.len()) > encoded.len() {
            return Err(Error::Misuse);
        }
        let mut bits = Secret::from(0u32);
        let mut size = 0;
        for &byte in decoded {
            *bits = (*bits << 8) | u32::from(byte);
            size += 8;
            while size >= BITS {
                size -= BITS;
                self.encode_index(*bits >> size, encoded);
            }
            *bits &= (1 << size) - 1;
        }
        if size > 0 {
            self.encode_index(*bits << (BITS - size), encoded);
        }
        if padded {
            self.add_padding(encoded);
        }
        Ok(&encoded[..self.offset])
    }

    fn encoded_size(padded: bool, decoded_size: usize) -> usize {
        let bits = decoded_size * 8;
        if padded {
            GROUPS * bits.div_ceil(BITS * GROUPS)
        } else {
            bits.div_ceil(BITS)
        }
    }

    fn add_padding(&mut self, encoded: &mut [u8]) {
        let remainder = self.offset % GROUPS;
        if remainder > 0 {
            let padding_size = GROUPS - remainder;
            for _ in 0..padding_size {
                self.push(PADDING_BYTE, encoded);
            }
        }
    }

    fn encode_index(&mut self, index: u32, encoded: &mut [u8]) {
        let index = (index & Self::MASK) as u8;
        let character = self.alphabet.iter().fold(0, |character, range| {
            let offset = index.wrapping_sub(range.index);
            Choice::less_than(offset, range.size)
                .select(character, range.character.wrapping_add(offset))
        });
        self.push(character, encoded);
    }

    fn push(&mut self, byte: u8, target: &mut [u8]) {
        target[self.offset] = byte;
        self.offset += 1;
    }

    fn decode<'a>(
        mut self,
        padded: bool,
        encoded: &[u8],
        decoded: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let unpadded_size = Self::unpadded_size(padded, encoded)?;
        let decoded_size = Self::decoded_size(unpadded_size);
        if decoded_size > decoded.len() {
            return Err(Error::Misuse);
        }
        let mut error = Choice::FALSE;
        let mut bits = Secret::from(0u32);
        let mut size = 0;
        for &character in &encoded[..unpadded_size] {
            let index = self.find_index(&mut error, character);
            *bits = (*bits << BITS) | u32::from(index);
            size += BITS;
            if size >= 8 {
                size -= 8;
                self.push((*bits >> size) as u8, decoded);
                *bits &= (1 << size) - 1;
            }
        }
        error |= Choice::nonzero(*bits);
        if declassify(error).to_bool() {
            wipe(decoded);
            return Err(Error::Encoding);
        }
        Ok(&decoded[..self.offset])
    }

    fn decoded_size(unpadded_size: usize) -> usize {
        (unpadded_size * BITS) / 8
    }

    fn unpadded_size(padded: bool, encoded: &[u8]) -> Result<usize, Error> {
        let mut reached_padding = Choice::FALSE;
        let mut padding_size = 0;
        let mut error = Choice::FALSE;
        for &b in encoded {
            let is_padding = Choice::eq(b, PADDING_BYTE);
            error |= reached_padding & !is_padding;
            reached_padding |= is_padding;
            padding_size += is_padding.select(0, 1);
        }
        let padding_size = declassify(padding_size);
        let unpadded_size = encoded.len() - padding_size;
        let remainder = unpadded_size % GROUPS;
        let expected_padding = if padded {
            (GROUPS - remainder) % GROUPS
        } else {
            0
        };
        let complete = (remainder * BITS) % 8 < BITS;
        if declassify(error).to_bool() || !complete || padding_size != expected_padding {
            return Err(Error::Encoding);
        }
        Ok(unpadded_size)
    }

    fn find_index(&self, error: &mut Choice, character: u8) -> u8 {
        let character = Self::normalize(character);
        let mut index = 0;
        let mut found = Choice::FALSE;
        for range in self.alphabet {
            let offset = character.wrapping_sub(range.character);
            let is_match = Choice::less_than(offset, range.size);
            index = is_match.select(index, range.index.wrapping_add(offset));
            found |= is_match;
        }
        *error |= !found;
        index
    }

    fn normalize(byte: u8) -> u8 {
        if BITS != 4 {
            return byte;
        }
        let is_uppercase = !Choice::less_than(byte, b'A') & Choice::less_than(byte, b'F' + 1);
        byte ^ (is_uppercase.mask::<u8>() & 32)
    }
}

type Base64 = Base<6, 4>;
type Base32 = Base<5, 8>;
type Base16 = Base<4, 2>;

fn base64(url_safe: bool) -> Base64 {
    if url_safe {
        Base64::new(&BASE64_ALPHABET_URL)
    } else {
        Base64::new(&BASE64_ALPHABET)
    }
}

fn base32() -> Base32 {
    Base32::new(&BASE32_ALPHABET)
}

fn base16() -> Base16 {
    Base16::new(&BASE16_ALPHABET)
}

pub fn base64_encode<'a>(
    url_safe: bool,
    padded: bool,
    bytes: &[u8],
    encoded: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    let base = base64(url_safe);
    base.encode(padded, bytes, encoded)
}

pub fn base64_decode<'a>(
    url_safe: bool,
    padded: bool,
    encoded: &[u8],
    decoded: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    let base = base64(url_safe);
    base.decode(padded, encoded, decoded)
}

pub fn base32_encode<'a>(
    padded: bool,
    decoded: &[u8],
    encoded: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    let base = base32();
    base.encode(padded, decoded, encoded)
}

pub fn base32_decode<'a>(
    padded: bool,
    encoded: &[u8],
    decoded: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    let base = base32();
    base.decode(padded, encoded, decoded)
}

pub fn base16_encode<'a>(decoded: &[u8], encoded: &'a mut [u8]) -> Result<&'a [u8], Error> {
    let base = base16();
    base.encode(false, decoded, encoded)
}

pub fn base16_decode<'a>(encoded: &[u8], decoded: &'a mut [u8]) -> Result<&'a [u8], Error> {
    let base = base16();
    base.decode(false, encoded, decoded)
}
