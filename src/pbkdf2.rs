use crate::{
    hmac::{HmacSha256, HmacSha512},
    traits::{Digest, KeyInit},
    xor::xor_mut,
};

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
    fn test_pbkdf2_hmac_sha256() {
        todo!()
    }

    #[test]
    fn test_pbkdf2_hmac_sha512() {
        todo!()
    }
}
