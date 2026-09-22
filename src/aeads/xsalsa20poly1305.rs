use crate::{aeads::Aead, ciphers::XSalsa20, macs::Poly1305, traits::CryptoRng};

pub type XSalsa20Poly1305 = Aead<XSalsa20, Poly1305>;

impl XSalsa20Poly1305 {
    pub fn generate_nonce(rng: &mut impl CryptoRng) -> [u8; 24] {
        let mut nonce = [0u8; 24];
        rng.fill(&mut nonce);
        nonce
    }
}

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    // https://github.com/jedisct1/libsodium/blob/master/test/default/secretbox.c

    const KEY: [u8; 32] = hex!("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389");
    const NONCE: [u8; 24] = hex!("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");
    const PLAINTEXT: [u8; 131] = hex!(
        "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc
        e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31
        0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde
        048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864
        5e0705"
    );
    const CIPHERTEXT: [u8; 131] = hex!(
        "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a
        c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738
        b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da
        99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74
        e355a5"
    );
    const TAG: [u8; 16] = hex!("f3ffc7703f9400e52a7dfb4b3d3305d9");

    #[test]
    fn test_xsalsa20poly1305() {
        let mut message = PLAINTEXT;
        let tag = XSalsa20Poly1305::encrypt(&KEY, &NONCE, None, &mut message);
        assert_eq!(message, CIPHERTEXT);
        assert_eq!(tag, TAG);
        let verified = XSalsa20Poly1305::decrypt(&KEY, &NONCE, None, &mut message, &tag);
        assert!(verified);
        assert_eq!(message, PLAINTEXT);
    }
}
