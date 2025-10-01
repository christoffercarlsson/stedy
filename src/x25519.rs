use crate::{curve25519::Curve25519, rng::Rng};

const A24: Curve25519 = Curve25519([121665, 0, 0, 0, 0]);
const BASE_POINT: Curve25519 = Curve25519([9, 0, 0, 0, 0]);

pub fn x25519_generate_key_pair(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut rng = Rng::from(seed);
    let mut private_key = [0u8; 32];
    rng.fill(&mut private_key);
    let public_key = x25519_public_key(&private_key);
    (private_key, public_key)
}

pub fn x25519_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    scalar_mult(private_key, BASE_POINT)
}

pub fn x25519_key_exchange(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    let public_point = Curve25519::from(public_key);
    scalar_mult(private_key, public_point)
}

fn scalar_mult(k: &[u8; 32], u: Curve25519) -> [u8; 32] {
    let mut scalar = *k;
    clamp(&mut scalar);
    let x1 = u;
    let mut x2 = Curve25519::ONE;
    let mut z2 = Curve25519::ZERO;
    let mut x3 = u;
    let mut z3 = Curve25519::ONE;
    let mut swap = 0u64;
    for i in (0..255).rev() {
        let byte_index = i / 8;
        let bit_index = i % 8;
        let bit = ((scalar[byte_index] >> bit_index) & 1) as u64;
        swap ^= bit;
        Curve25519::swap(&mut x2, &mut x3, swap);
        Curve25519::swap(&mut z2, &mut z3, swap);
        swap = bit;
        let a = x2 + z2;
        let aa = a.square();
        let b = x2 - z2;
        let bb = b.square();
        let e = aa - bb;
        let c = x3 + z3;
        let d = x3 - z3;
        let da = d * a;
        let cb = c * b;
        x3 = (da + cb).square();
        z3 = x1 * (da - cb).square();
        x2 = aa * bb;
        z2 = e * (aa + A24 * e);
    }
    Curve25519::swap(&mut x2, &mut x3, swap);
    Curve25519::swap(&mut z2, &mut z3, swap);
    let result = x2 / z2;
    result.into()
}

pub fn clamp(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://datatracker.ietf.org/doc/html/rfc7748#section-5.2

    #[test]
    fn test_scalar_mult_tc1() {
        let k = [
            165, 70, 227, 107, 240, 82, 124, 157, 59, 22, 21, 75, 130, 70, 94, 221, 98, 20, 76, 10,
            193, 252, 90, 24, 80, 106, 34, 68, 186, 68, 154, 196,
        ];
        let u = Curve25519::from(&[
            230, 219, 104, 103, 88, 48, 48, 219, 53, 148, 193, 164, 36, 177, 95, 124, 114, 102, 36,
            236, 38, 179, 53, 59, 16, 169, 3, 166, 208, 171, 28, 76,
        ]);
        let result = scalar_mult(&k, u);
        assert_eq!(
            result,
            [
                195, 218, 85, 55, 157, 233, 198, 144, 142, 148, 234, 77, 242, 141, 8, 79, 50, 236,
                207, 3, 73, 28, 113, 247, 84, 180, 7, 85, 119, 162, 133, 82,
            ]
        );
    }

    #[test]
    fn test_scalar_mult_tc2() {
        let k = [
            75, 102, 233, 212, 209, 180, 103, 60, 90, 210, 38, 145, 149, 125, 106, 245, 193, 27,
            100, 33, 224, 234, 1, 212, 44, 164, 22, 158, 121, 24, 186, 13,
        ];
        let u = Curve25519::from(&[
            229, 33, 15, 18, 120, 104, 17, 211, 244, 183, 149, 157, 5, 56, 174, 44, 49, 219, 231,
            16, 111, 192, 60, 62, 252, 76, 213, 73, 199, 21, 164, 147,
        ]);
        let result = scalar_mult(&k, u);
        assert_eq!(
            result,
            [
                149, 203, 222, 148, 118, 232, 144, 125, 122, 173, 228, 92, 180, 184, 115, 248, 139,
                89, 90, 104, 121, 159, 161, 82, 230, 248, 247, 100, 122, 172, 121, 87
            ]
        );
    }

    #[test]
    fn test_x25519_iter() {
        let k: [u8; 32] = Curve25519::from(BASE_POINT).into();
        let u: [u8; 32] = Curve25519::from(BASE_POINT).into();
        let result = x25519_key_exchange(&k, &u);
        assert_eq!(
            result,
            [
                66, 44, 142, 122, 98, 39, 215, 188, 161, 53, 11, 62, 43, 183, 39, 159, 120, 151,
                184, 123, 182, 133, 75, 120, 60, 96, 232, 3, 17, 174, 48, 121
            ]
        );
    }

    #[test]
    fn test_x25519_iter_1k() {
        let mut k: [u8; 32] = Curve25519::from(BASE_POINT).into();
        let mut u: [u8; 32] = Curve25519::from(BASE_POINT).into();
        for _ in 0..1000 {
            let result = x25519_key_exchange(&k, &u);
            u = k;
            k = result;
        }
        assert_eq!(
            k,
            [
                104, 76, 245, 155, 168, 51, 9, 85, 40, 0, 239, 86, 111, 47, 77, 60, 28, 56, 135,
                196, 147, 96, 227, 135, 95, 46, 185, 77, 153, 83, 44, 81
            ]
        );
    }

    // #[test]
    // fn test_x25519_iter_1m() {
    //     let mut k: [u8; 32] = Curve25519::from(BASE_POINT).into();
    //     let mut u: [u8; 32] = Curve25519::from(BASE_POINT).into();
    //     for _ in 0..1000000 {
    //         let result = x25519_key_exchange(&k, &u);
    //         u = k;
    //         k = result;
    //     }
    //     assert_eq!(
    //         k,
    //         [
    //             124, 57, 17, 224, 171, 37, 134, 253, 134, 68, 151, 41, 126, 87, 94, 111, 59, 198,
    //             1, 192, 136, 60, 48, 223, 95, 77, 210, 210, 79, 102, 84, 36,
    //         ]
    //     );
    // }

    #[test]
    fn test_x25519() {
        let alice_private_key = [
            119, 7, 109, 10, 115, 24, 165, 125, 60, 22, 193, 114, 81, 178, 102, 69, 223, 76, 47,
            135, 235, 192, 153, 42, 177, 119, 251, 165, 29, 185, 44, 42,
        ];
        let alice_public_key = [
            133, 32, 240, 9, 137, 48, 167, 84, 116, 139, 125, 220, 180, 62, 247, 90, 13, 191, 58,
            13, 38, 56, 26, 244, 235, 164, 169, 142, 170, 155, 78, 106,
        ];
        let bob_private_key = [
            93, 171, 8, 126, 98, 74, 138, 75, 121, 225, 127, 139, 131, 128, 14, 230, 111, 59, 177,
            41, 38, 24, 182, 253, 28, 47, 139, 39, 255, 136, 224, 235,
        ];
        let bob_public_key = [
            222, 158, 219, 125, 123, 125, 193, 180, 211, 91, 97, 194, 236, 228, 53, 55, 63, 131,
            67, 200, 91, 120, 103, 77, 173, 252, 126, 20, 111, 136, 43, 79,
        ];
        let shared_secret = [
            74, 93, 157, 91, 164, 206, 45, 225, 114, 142, 59, 244, 128, 53, 15, 37, 224, 126, 33,
            201, 71, 209, 158, 51, 118, 240, 155, 60, 30, 22, 23, 66,
        ];
        let public_key = x25519_public_key(&alice_private_key);
        assert_eq!(public_key, alice_public_key);
        let public_key = x25519_public_key(&bob_private_key);
        assert_eq!(public_key, bob_public_key);
        let secret = x25519_key_exchange(&alice_private_key, &bob_public_key);
        assert_eq!(secret, shared_secret);
        let secret = x25519_key_exchange(&bob_private_key, &alice_public_key);
        assert_eq!(secret, shared_secret);
    }
}
