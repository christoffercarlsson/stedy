pub fn get_private_key(private_key: &mut [u8], key_pair: &[u8], private_key_size: usize) {
    private_key.copy_from_slice(&key_pair[..private_key_size]);
}

pub fn get_public_key(public_key: &mut [u8], key_pair: &[u8], private_key_size: usize) {
    public_key.copy_from_slice(&key_pair[private_key_size..]);
}

pub fn set_key_pair(
    key_pair: &mut [u8],
    private_key: &[u8],
    public_key: &[u8],
    private_key_size: usize,
) {
    key_pair[..private_key_size].copy_from_slice(private_key);
    key_pair[private_key_size..].copy_from_slice(public_key);
}
