use crate::{
    traits::{ByteArray, Digest, Hasher, KeyInit, Mac, Prf},
    utils::{verify, xor},
};

#[derive(Clone)]
pub struct Hmac<H: Hasher> {
    inner: H,
    outer: H,
}

impl<H: Hasher> Hmac<H> {
    pub fn new(key: &[u8]) -> Self {
        let mut k = H::Block::new();
        if key.len() > H::BLOCK_SIZE {
            let mut hasher = H::new();
            hasher.update(key);
            let key_digest = hasher.finalize();
            k.as_mut()
                .get_mut(..key_digest.as_ref().len())
                .expect("HMAC key digest fits within a block")
                .copy_from_slice(key_digest.as_ref());
        } else {
            k.as_mut()
                .get_mut(..key.len())
                .expect("HMAC key fits within a block")
                .copy_from_slice(key);
        }
        let mut inner_key = H::Block::new();
        let mut outer_key = H::Block::new();
        inner_key.as_mut().fill(54);
        outer_key.as_mut().fill(92);
        xor(inner_key.as_mut(), k.as_ref());
        xor(outer_key.as_mut(), k.as_ref());
        let mut inner = H::new();
        let mut outer = H::new();
        inner.update(inner_key.as_ref());
        outer.update(outer_key.as_ref());
        Self { inner, outer }
    }

    pub fn update(&mut self, message: &[u8]) {
        self.inner.update(message);
    }

    pub fn finalize_into(mut self, code: &mut [u8]) {
        let digest = self.inner.finalize();
        self.outer.update(digest.as_ref());
        self.outer.finalize_into(code);
    }

    pub fn finalize(self) -> H::Output {
        let mut code = H::Output::new();
        self.finalize_into(code.as_mut());
        code
    }

    pub fn verify(self, code: &H::Output) -> bool {
        verify(code.as_ref(), self.finalize().as_ref())
    }
}

impl<H: Hasher> KeyInit for Hmac<H> {
    fn new(key: &[u8]) -> Self {
        Self::new(key)
    }
}

impl<H: Hasher> Digest for Hmac<H> {
    const OUTPUT_SIZE: usize = H::OUTPUT_SIZE;

    type Output = H::Output;

    fn update(&mut self, message: &[u8]) {
        self.update(message);
    }

    fn finalize(self) -> Self::Output {
        self.finalize()
    }

    fn finalize_into(self, output: &mut [u8]) {
        self.finalize_into(output);
    }
}

impl<H: Hasher> Prf for Hmac<H> {}

impl<H: Hasher> Mac for Hmac<H> {
    fn verify(self, code: &Self::Output) -> bool {
        self.verify(code)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::hashes::{Sha256, Sha512},
        hex_literal::hex,
    };

    #[cfg(feature = "hazmat")]
    use crate::hashes::Sha1;

    fn calculate_code<H: Hasher>(key: &[u8], message: &[u8]) -> H::Output {
        let mut mac = Hmac::<H>::new(key);
        mac.update(message);
        mac.finalize()
    }

    fn verify_code<H: Hasher>(key: &[u8], message: &[u8], code: &H::Output) -> bool {
        let mut mac = Hmac::<H>::new(key);
        mac.update(message);
        mac.verify(code)
    }

    // https://datatracker.ietf.org/doc/html/rfc2202#section-3

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_hmac_sha1() {
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let message = hex!("4869205468657265");
        let code = calculate_code::<Sha1>(&key, &message);
        let verified = verify_code::<Sha1>(&key, &message, &code);
        assert!(verified);
        assert_eq!(code, hex!("b617318655057264e28bc0b6fb378c8ef146be00"));
    }

    // https://datatracker.ietf.org/doc/html/rfc4231

    #[test]
    fn test_hmac_sha256_tc1() {
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let message = hex!("4869205468657265");
        let code = calculate_code::<Sha256>(&key, &message);
        let verified = verify_code::<Sha256>(&key, &message, &code);
        assert!(verified);
        assert_eq!(
            code,
            hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }

    #[test]
    fn test_hmac_sha256_tc2() {
        let key = hex!("4a656665");
        let message = hex!("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
        let code = calculate_code::<Sha256>(&key, &message);
        let verified = verify_code::<Sha256>(&key, &message, &code);
        assert!(verified);
        assert_eq!(
            code,
            hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn test_hmac_sha256_tc3() {
        let key = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let message = hex!("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        let code = calculate_code::<Sha256>(&key, &message);
        let verified = verify_code::<Sha256>(&key, &message, &code);
        assert!(verified);
        assert_eq!(
            code,
            hex!("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
        );
    }

    #[test]
    fn test_hmac_sha256_tc4() {
        let key = hex!("0102030405060708090a0b0c0d0e0f10111213141516171819");
        let message = hex!("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
        let code = calculate_code::<Sha256>(&key, &message);
        let verified = verify_code::<Sha256>(&key, &message, &code);
        assert!(verified);
        assert_eq!(
            code,
            hex!("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
        );
    }

    #[test]
    fn test_hmac_sha256_tc5() {
        let key = hex!("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
        let message = hex!("546573742057697468205472756e636174696f6e");
        let code = calculate_code::<Sha256>(&key, &message);
        let verified = verify_code::<Sha256>(&key, &message, &code);
        assert!(verified);
        assert_eq!(code[..16], hex!("a3b6167473100ee06e0c796c2955552b"));
    }

    #[test]
    fn test_hmac_sha256_tc6() {
        let key = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let message = hex!("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374");
        let code = calculate_code::<Sha256>(&key, &message);
        let verified = verify_code::<Sha256>(&key, &message, &code);
        assert!(verified);
        assert_eq!(
            code,
            hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    #[test]
    fn test_hmac_sha256_tc7() {
        let key = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let message = hex!("5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e");
        let code = calculate_code::<Sha256>(&key, &message);
        let verified = verify_code::<Sha256>(&key, &message, &code);
        assert!(verified);
        assert_eq!(
            code,
            hex!("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")
        );
    }

    #[test]
    fn test_hmac_sha512_tc1() {
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let message = hex!("4869205468657265");
        let code = calculate_code::<Sha512>(&key, &message);
        let verified = verify_code::<Sha512>(&key, &message, &code);
        assert!(verified);
        assert_eq!(
            code,
            hex!("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")
        );
    }

    #[test]
    fn test_hmac_sha512_tc2() {
        let key = hex!("4a656665");
        let message = hex!("7768617420646f2079612077616e7420666f72206e6f7468696e673f");
        let code = calculate_code::<Sha512>(&key, &message);
        let verified = verify_code::<Sha512>(&key, &message, &code);
        assert!(verified);
        assert_eq!(
            code,
            hex!("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")
        );
    }

    #[test]
    fn test_hmac_sha512_tc3() {
        let key = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let message = hex!("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        let code = calculate_code::<Sha512>(&key, &message);
        let verified = verify_code::<Sha512>(&key, &message, &code);
        assert!(verified);
        assert_eq!(
            code,
            hex!("fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb")
        );
    }

    #[test]
    fn test_hmac_sha512_tc4() {
        let key = hex!("0102030405060708090a0b0c0d0e0f10111213141516171819");
        let message = hex!("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
        let code = calculate_code::<Sha512>(&key, &message);
        let verified = verify_code::<Sha512>(&key, &message, &code);
        assert!(verified);
        assert_eq!(
            code,
            hex!("b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd")
        );
    }

    #[test]
    fn test_hmac_sha512_tc5() {
        let key = hex!("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
        let message = hex!("546573742057697468205472756e636174696f6e");
        let code = calculate_code::<Sha512>(&key, &message);
        let verified = verify_code::<Sha512>(&key, &message, &code);
        assert!(verified);
        assert_eq!(code[..16], hex!("415fad6271580a531d4179bc891d87a6"));
    }

    #[test]
    fn test_hmac_sha512_tc6() {
        let key = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let message = hex!("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374");
        let code = calculate_code::<Sha512>(&key, &message);
        let verified = verify_code::<Sha512>(&key, &message, &code);
        assert!(verified);
        assert_eq!(
            code,
            hex!("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598")
        );
    }

    #[test]
    fn test_hmac_sha512_tc7() {
        let key = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let message = hex!("5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e");
        let code = calculate_code::<Sha512>(&key, &message);
        let verified = verify_code::<Sha512>(&key, &message, &code);
        assert!(verified);
        assert_eq!(
            code,
            hex!("e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58")
        );
    }
}
