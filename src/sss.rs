use crate::{
    chacha20poly1305::{chacha20poly1305_decrypt, chacha20poly1305_encrypt},
    curve25519::Curve25519,
    rng::Rng,
    x25519::{clamp, derive_secret_key, key_pair_from_rng},
};

pub fn sss_split<const N: usize, const K: usize>(
    seed: [u8; 32],
    secret: &[u8; 32],
) -> [[u8; 116]; N] {
    let mut rng = Rng::from(seed);
    let private_key = generate_private_key(&mut rng);
    let public_key = generate_public_key(&mut rng);
    let secret_key = derive_secret_key(&private_key, &public_key);
    let coefficients = calculate_coefficients::<K>(&mut rng, &private_key);
    let mut shares = [[0u8; 116]; N];
    for i in 0..N {
        let x = (i + 1) as u32;
        calculate_share::<K>(
            secret,
            &public_key,
            &secret_key,
            x,
            &coefficients,
            &mut shares[i],
        );
    }
    shares
}

fn generate_private_key(rng: &mut Rng) -> [u8; 32] {
    let (private_key, _) = key_pair_from_rng(rng);
    private_key
}

fn generate_public_key(rng: &mut Rng) -> [u8; 32] {
    let (_, public_key) = key_pair_from_rng(rng);
    public_key
}

fn calculate_coefficients<const K: usize>(
    rng: &mut Rng,
    private_key: &[u8; 32],
) -> [Curve25519; K] {
    let mut c = [[0u8; 32]; K];
    c[0].copy_from_slice(private_key);
    clamp(&mut c[0]);
    for i in 1..K {
        rng.fill(&mut c[i]);
        clamp(&mut c[i]);
    }
    c.map(|bytes| Curve25519::from(&bytes))
}

fn calculate_share<const K: usize>(
    secret: &[u8; 32],
    public_key: &[u8; 32],
    secret_key: &[u8; 32],
    x: u32,
    coefficients: &[Curve25519; K],
    share: &mut [u8; 116],
) {
    let shamir_share = calculate_shamir_share(x, coefficients);
    let mut nonce = [0u8; 12];
    nonce[8..12].copy_from_slice(&x.to_be_bytes());
    share[68..100].copy_from_slice(secret);
    let tag = chacha20poly1305_encrypt(secret_key, &nonce, None, &mut share[68..100]);
    share[100..116].copy_from_slice(&tag);
    share[0..4].copy_from_slice(&nonce[8..12]);
    share[4..36].copy_from_slice(&shamir_share);
    share[36..68].copy_from_slice(public_key);
}

fn calculate_shamir_share<const K: usize>(x: u32, coefficients: &[Curve25519; K]) -> [u8; 32] {
    let mut share = coefficients[0];
    for i in 1..K {
        share += coefficients[i] * Curve25519::from(x.pow(i as u32));
    }
    share.into()
}

pub fn sss_combine<const K: usize>(shares: &[[u8; 116]; K]) -> Option<[u8; 32]> {
    let secret_key = recover_secret_key(shares);
    let mut nonce = [0u8; 12];
    nonce[8..12].copy_from_slice(&shares[0][0..4]);
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&shares[0][68..100]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&shares[0][100..116]);
    if chacha20poly1305_decrypt(&secret_key, &nonce, None, &mut secret, &tag) {
        Some(secret)
    } else {
        None
    }
}

fn recover_secret_key<const K: usize>(shares: &[[u8; 116]; K]) -> [u8; 32] {
    let private_key = recover_private_key(shares);
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&shares[0][36..68]);
    derive_secret_key(&private_key, &public_key)
}

fn recover_private_key<const K: usize>(shares: &[[u8; 116]; K]) -> [u8; 32] {
    let mut private_key = Curve25519::ZERO;
    for j in 0..K {
        let xj = read_index(&shares[j]);
        let yj = read_bytes(&shares[j]);
        let mut lambda = Curve25519::ONE;
        for m in 0..K {
            if m == j {
                continue;
            }
            let xm = read_index(&shares[m]);
            lambda *= xm / (xm - xj);
        }
        private_key += yj * lambda;
    }
    private_key.into()
}

fn read_index(share: &[u8; 116]) -> Curve25519 {
    let index = u32::from_be_bytes([share[0], share[1], share[2], share[3]]);
    Curve25519::from(index)
}

fn read_bytes(share: &[u8; 116]) -> Curve25519 {
    Curve25519::from(&share[4..36])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sss() {
        let seed = [0u8; 32];
        let secret = [
            136, 216, 83, 226, 72, 2, 31, 41, 30, 4, 133, 24, 79, 9, 12, 64, 255, 15, 234, 195, 20,
            214, 37, 199, 82, 42, 190, 148, 35, 201, 11, 121,
        ];
        let shares = sss_split::<3, 2>(seed, &secret);
        let result = sss_combine(&[shares[2], shares[1]]).unwrap();
        assert_eq!(result, secret);
    }
}
