use crate::{curve25519::Curve25519, rng::Rng, x25519::clamp};

#[cfg(feature = "getrandom")]
pub fn sss_split<const N: usize, const K: usize>(secret: &[u8; 32]) -> [[u8; 36]; N] {
    let mut rng = Rng::new().unwrap();
    generate_shares::<N, K>(&mut rng, secret)
}

#[cfg(not(feature = "getrandom"))]
pub fn sss_split<const N: usize, const K: usize>(
    seed: [u8; 32],
    secret: &[u8; 32],
) -> [[u8; 36]; N] {
    let mut rng = Rng::from(seed);
    generate_shares::<N, K>(&mut rng, secret)
}

fn generate_shares<const N: usize, const K: usize>(
    rng: &mut Rng,
    secret: &[u8; 32],
) -> [[u8; 36]; N] {
    let c = calculate_coefficients(rng, *secret);
    let mut shares = [[0u8; 36]; N];
    for i in 0..N {
        let x = (i + 1) as u32;
        calculate_share::<K>(x, &c, &mut shares[i]);
    }
    shares
}

fn calculate_coefficients<const K: usize>(rng: &mut Rng, mut secret: [u8; 32]) -> [Curve25519; K] {
    clamp(&mut secret);
    let mut c = [[0u8; 32]; K];
    c[0] = secret;
    for i in 1..K {
        rng.fill(&mut c[i]);
    }
    c.map(|bytes| Curve25519::from(&bytes))
}

fn calculate_share<const K: usize>(x: u32, c: &[Curve25519; K], share: &mut [u8; 36]) {
    let mut t = c[0];
    for i in 1..K {
        t += c[i] * Curve25519::from(x.pow(i as u32));
    }
    let bytes: [u8; 32] = t.into();
    share[0..4].copy_from_slice(&x.to_be_bytes());
    share[4..36].copy_from_slice(&bytes);
}

pub fn sss_combine<const K: usize>(shares: &[[u8; 36]; K]) -> [u8; 32] {
    let mut secret = Curve25519::zero();
    for j in 0..K {
        let xj = read_index(&shares[j]);
        let yj = read_bytes(&shares[j]);
        let mut lambda = Curve25519::one();
        for m in 0..K {
            if m == j {
                continue;
            }
            let xm = read_index(&shares[m]);
            lambda *= xm / (xm - xj);
        }
        secret += yj * lambda;
    }
    secret.into()
}

#[inline(always)]
fn read_index(share: &[u8; 36]) -> Curve25519 {
    let index = u32::from_be_bytes([share[0], share[1], share[2], share[3]]);
    Curve25519::from(index)
}

#[inline(always)]
fn read_bytes(share: &[u8; 36]) -> Curve25519 {
    Curve25519::from(&share[4..36])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x25519::x25519_key_exchange;

    #[test]
    fn test_sss() {
        let secret = [
            136, 216, 83, 226, 72, 2, 31, 41, 30, 4, 133, 24, 79, 9, 12, 64, 255, 15, 234, 195, 20,
            214, 37, 199, 82, 42, 190, 148, 35, 201, 11, 121,
        ];
        let shares = sss_split::<3, 2>(&secret);
        let result = sss_combine(&[shares[2], shares[1]]);
        assert_eq!(result, secret);
    }

    #[test]
    fn test_sss_key_exchange() {
        let private_key = [
            187, 26, 123, 182, 188, 166, 140, 90, 67, 163, 206, 196, 135, 52, 179, 199, 168, 255,
            10, 206, 36, 75, 186, 93, 223, 168, 101, 186, 20, 202, 188, 140,
        ];
        let public_key = [
            23, 51, 74, 39, 79, 208, 23, 47, 213, 82, 102, 99, 53, 126, 217, 31, 31, 242, 86, 195,
            1, 22, 177, 188, 230, 120, 233, 205, 44, 141, 43, 13,
        ];
        let shared_secret = x25519_key_exchange(&private_key, &public_key);
        let shares = sss_split::<6, 3>(&private_key);
        let key = sss_combine(&[shares[2], shares[1], shares[3]]);
        let secret = x25519_key_exchange(&key, &public_key);
        assert_ne!(key, private_key);
        assert_eq!(secret, shared_secret);
    }
}
