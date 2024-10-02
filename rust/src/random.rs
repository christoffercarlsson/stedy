use rand_core::CryptoRngCore;

pub fn get_random_bytes<R: CryptoRngCore>(mut csprng: R, bytes: &mut [u8]) {
    csprng.fill_bytes(bytes);
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use super::*;
    use alloc::vec;
    use rand::rngs::OsRng;

    #[test]
    fn test_random_bytes() {
        let mut bytes = vec![0; 16];
        get_random_bytes(OsRng, &mut bytes);
        assert_ne!(bytes, vec![0; 16]);
    }
}
