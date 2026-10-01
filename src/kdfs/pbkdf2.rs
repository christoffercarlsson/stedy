use crate::{traits::Prf, utils::xor};

pub fn pbkdf2<P>(password: &[u8], salt: &[u8], iterations: usize, output: &mut [u8])
where
    P: Prf + Clone,
{
    let prf = P::new(password);
    for (i, chunk) in output.chunks_mut(P::OUTPUT_SIZE).enumerate() {
        f(&prf, salt, iterations, i as u32, chunk);
    }
}

fn f<P>(prf: &P, salt: &[u8], iterations: usize, i: u32, chunk: &mut [u8])
where
    P: Prf + Clone,
{
    let mut u = {
        let mut p = prf.clone();
        p.update(salt);
        p.update(&(i + 1).to_be_bytes());
        let u = p.finalize();
        xor(chunk, u.as_ref());
        u
    };
    for _ in 1..iterations {
        let mut p = prf.clone();
        p.update(u.as_ref());
        u = p.finalize();
        xor(chunk, u.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            hashes::{Sha256, Sha512},
            macs::Hmac,
        },
        hex_literal::hex,
    };

    #[cfg(feature = "hazmat")]
    use crate::hashes::Sha1;

    // https://datatracker.ietf.org/doc/html/rfc6070

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_pbkdf2_hmac_sha1_tc1() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 1;
        let mut output = [0u8; 20];
        pbkdf2::<Hmac<Sha1>>(password, salt, iterations, &mut output);
        assert_eq!(output, hex!("0c60c80f961f0e71f3a9b524af6012062fe037a6"));
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_pbkdf2_hmac_sha1_tc2() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 2;
        let mut output = [0u8; 20];
        pbkdf2::<Hmac<Sha1>>(password, salt, iterations, &mut output);
        assert_eq!(output, hex!("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"));
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_pbkdf2_hmac_sha1_tc3() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 4096;
        let mut output = [0u8; 20];
        pbkdf2::<Hmac<Sha1>>(password, salt, iterations, &mut output);
        assert_eq!(output, hex!("4b007901b765489abead49d926f721d065a429c1"));
    }

    // #[cfg(feature = "hazmat")]
    // #[test]
    // fn test_pbkdf2_hmac_sha1_tc4() {
    //     let password = b"password";
    //     let salt = b"salt";
    //     let iterations = 16777216;
    //     let mut output = [0u8; 20];
    //     pbkdf2_hmac_sha1(password, salt, iterations, &mut output);
    //     assert_eq!(
    //         output,
    //         [
    //             238, 254, 61, 97, 205, 77, 164, 228, 233, 148, 91, 61, 107, 162, 21, 140, 38, 52,
    //             233, 132
    //         ]
    //     );
    // }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_pbkdf2_hmac_sha1_tc5() {
        let password = b"passwordPASSWORDpassword";
        let salt = b"saltSALTsaltSALTsaltSALTsaltSALTsalt";
        let iterations = 4096;
        let mut output = [0u8; 25];
        pbkdf2::<Hmac<Sha1>>(password, salt, iterations, &mut output);
        assert_eq!(
            output,
            hex!("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")
        );
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_pbkdf2_hmac_sha1_tc6() {
        let password = b"pass\0word";
        let salt = b"sa\0lt";
        let iterations = 4096;
        let mut output = [0u8; 16];
        pbkdf2::<Hmac<Sha1>>(password, salt, iterations, &mut output);
        assert_eq!(output, hex!("56fa6aa75548099dcc37d7f03425e0c3"));
    }

    #[test]
    fn test_pbkdf2_hmac_sha256() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 4096;
        let mut output = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut output);
        assert_eq!(
            output,
            hex!("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
        );
    }

    #[test]
    fn test_pbkdf2_hmac_sha512() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 4096;
        let mut output = [0u8; 64];
        pbkdf2::<Hmac<Sha512>>(password, salt, iterations, &mut output);
        assert_eq!(
            output,
            hex!("d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5")
        );
    }
}
