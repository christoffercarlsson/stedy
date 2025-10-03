use crate::{
    hmac::{HmacSha1, HmacSha256, HmacSha512},
    traits::{Digest, KeyInit},
    xor::xor_mut,
};

pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: usize, output: &mut [u8]) {
    pbkdf2::<HmacSha1, 20>(password, salt, iterations, output);
}

pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: usize, output: &mut [u8]) {
    pbkdf2::<HmacSha256, 32>(password, salt, iterations, output);
}

pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: usize, output: &mut [u8]) {
    pbkdf2::<HmacSha512, 64>(password, salt, iterations, output);
}

fn pbkdf2<P, const OUTPUT_SIZE: usize>(
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    output: &mut [u8],
) where
    P: KeyInit + Digest<OUTPUT_SIZE> + Clone,
{
    let prf = P::new(password);
    for (i, chunk) in output.chunks_mut(OUTPUT_SIZE).enumerate() {
        f(&prf, salt, iterations, i as u32, chunk);
    }
}

fn f<P, const OUTPUT_SIZE: usize>(prf: &P, salt: &[u8], iterations: usize, i: u32, chunk: &mut [u8])
where
    P: KeyInit + Digest<OUTPUT_SIZE> + Clone,
{
    let mut u = {
        let mut p = prf.clone();
        p.update(salt);
        p.update(&(i + 1).to_be_bytes());
        let u = p.finalize();
        xor_mut(chunk, &u);
        u
    };
    for _ in 1..iterations {
        let mut p = prf.clone();
        p.update(&u);
        u = p.finalize();
        xor_mut(chunk, &u);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://datatracker.ietf.org/doc/html/rfc6070

    #[test]
    fn test_pbkdf2_hmac_sha1_tc1() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 1;
        let mut output = [0u8; 20];
        pbkdf2_hmac_sha1(password, salt, iterations, &mut output);
        assert_eq!(
            output,
            [
                12, 96, 200, 15, 150, 31, 14, 113, 243, 169, 181, 36, 175, 96, 18, 6, 47, 224, 55,
                166
            ]
        );
    }

    #[test]
    fn test_pbkdf2_hmac_sha1_tc2() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 2;
        let mut output = [0u8; 20];
        pbkdf2_hmac_sha1(password, salt, iterations, &mut output);
        assert_eq!(
            output,
            [
                234, 108, 1, 77, 199, 45, 111, 140, 205, 30, 217, 42, 206, 29, 65, 240, 216, 222,
                137, 87
            ]
        );
    }

    #[test]
    fn test_pbkdf2_hmac_sha1_tc3() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 4096;
        let mut output = [0u8; 20];
        pbkdf2_hmac_sha1(password, salt, iterations, &mut output);
        assert_eq!(
            output,
            [
                75, 0, 121, 1, 183, 101, 72, 154, 190, 173, 73, 217, 38, 247, 33, 208, 101, 164,
                41, 193
            ]
        );
    }

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

    #[test]
    fn test_pbkdf2_hmac_sha1_tc5() {
        let password = b"passwordPASSWORDpassword";
        let salt = b"saltSALTsaltSALTsaltSALTsaltSALTsalt";
        let iterations = 4096;
        let mut output = [0u8; 25];
        pbkdf2_hmac_sha1(password, salt, iterations, &mut output);
        assert_eq!(
            output,
            [
                61, 46, 236, 79, 228, 28, 132, 155, 128, 200, 216, 54, 98, 192, 228, 74, 139, 41,
                26, 150, 76, 242, 240, 112, 56
            ]
        );
    }

    #[test]
    fn test_pbkdf2_hmac_sha1_tc6() {
        let password = b"pass\0word";
        let salt = b"sa\0lt";
        let iterations = 4096;
        let mut output = [0u8; 16];
        pbkdf2_hmac_sha1(password, salt, iterations, &mut output);
        assert_eq!(
            output,
            [86, 250, 106, 167, 85, 72, 9, 157, 204, 55, 215, 240, 52, 37, 224, 195]
        );
    }

    #[test]
    fn test_pbkdf2_hmac_sha256() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 4096;
        let mut output = [0u8; 32];
        pbkdf2_hmac_sha256(password, salt, iterations, &mut output);
        assert_eq!(
            output,
            [
                197, 228, 120, 213, 146, 136, 200, 65, 170, 83, 13, 182, 132, 92, 76, 141, 150, 40,
                147, 160, 1, 206, 78, 17, 164, 150, 56, 115, 170, 152, 19, 74
            ]
        );
    }

    #[test]
    fn test_pbkdf2_hmac_sha512() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 4096;
        let mut output = [0u8; 64];
        pbkdf2_hmac_sha512(password, salt, iterations, &mut output);
        assert_eq!(
            output,
            [
                209, 151, 177, 179, 61, 176, 20, 62, 1, 139, 18, 243, 209, 209, 71, 158, 108, 222,
                189, 204, 151, 197, 192, 248, 127, 105, 2, 224, 114, 244, 87, 181, 20, 63, 48, 96,
                38, 65, 179, 213, 92, 211, 53, 152, 140, 179, 107, 132, 55, 96, 96, 236, 213, 50,
                224, 57, 183, 66, 162, 57, 67, 74, 242, 213
            ]
        );
    }
}
