#![no_main]

use {
    libfuzzer_sys::fuzz_target,
    stedy::encoding::{Encoding, decode, encode},
};

const ENCODINGS: [Encoding; 8] = [
    Encoding::Hex,
    Encoding::Base16,
    Encoding::Base32,
    Encoding::Base32Unpadded,
    Encoding::Base64,
    Encoding::Base64Unpadded,
    Encoding::Base64Url,
    Encoding::Base64UrlUnpadded,
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    let encoding = ENCODINGS[usize::from(selector) % ENCODINGS.len()];
    let mut decoded = vec![0u8; input.len()];
    let mut encoded = vec![0u8; input.len() * 2 + 8];
    let mut again = vec![0u8; input.len()];
    if let Ok(decoded) = decode(encoding, input, &mut decoded) {
        let encoded = encode(encoding, decoded, &mut encoded).unwrap();
        assert_eq!(decode(encoding, encoded, &mut again).unwrap(), decoded);
    }
    let encoded = encode(encoding, input, &mut encoded).unwrap();
    assert_eq!(decode(encoding, encoded, &mut again).unwrap(), input);
});
