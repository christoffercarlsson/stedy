#![no_main]

use {
    libfuzzer_sys::fuzz_target,
    stedy::padding::{pad_to_block, unpad},
};

fuzz_target!(|data: &[u8]| {
    if let Ok(unpadded) = unpad(data) {
        let (marker, zeros) = data[unpadded.len()..].split_first().unwrap();
        assert_eq!(*marker, 0x80);
        assert!(zeros.iter().all(|&byte| byte == 0));
    }
    let Some((&block_size, message)) = data.split_first() else {
        return;
    };
    let block_size = usize::from(block_size).max(1);
    let mut buffer = vec![0u8; message.len() + block_size];
    let padded = pad_to_block(message, &mut buffer, block_size).unwrap();
    assert_eq!(padded.len() % block_size, 0);
    assert_eq!(unpad(padded).unwrap(), message);
});
