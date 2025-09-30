use crate::{
    curve25519::Curve25519,
    rng::Rng,
    sha512::{sha512, Sha512},
    x25519::clamp,
};
use core::ops::{Add, Index, IndexMut, Mul};

pub fn ed25519_generate_key_pair(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut rng = Rng::from(seed);
    let mut private_key = [0u8; 32];
    rng.fill(&mut private_key);
    let public_key = ed25519_public_key(&private_key);
    (private_key, public_key)
}

pub fn ed25519_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let g = EdwardsPoint::BASE_POINT;
    let (a, _) = expand(private_key);
    (g * a).compress()
}

pub fn ed25519_sign(private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let g = EdwardsPoint::BASE_POINT;
    let (a, prefix) = expand(private_key);
    let ga = (g * a).compress();
    let mut state = Sha512::new();
    state.update(&prefix);
    state.update(message);
    let r = Scalar::from(state.finalize());
    let gr = (g * r).compress();
    let mut state = Sha512::new();
    state.update(&gr);
    state.update(&ga);
    state.update(message);
    let h = Scalar::from(state.finalize());
    let s: [u8; 32] = (r + h * a).into();
    let mut signature = [0u8; 64];
    signature[0..32].copy_from_slice(&gr);
    signature[32..64].copy_from_slice(&s);
    signature
}

pub fn ed25519_verify(message: &[u8], public_key: &[u8; 32], signature: &[u8; 64]) -> bool {
    let mut gr = [0u8; 32];
    let mut s = [0u8; 32];
    gr.copy_from_slice(&signature[0..32]);
    s.copy_from_slice(&signature[32..64]);
    let (a, valid_a) = EdwardsPoint::decompress(public_key);
    let (r, valid_r) = EdwardsPoint::decompress(&gr);
    let g = EdwardsPoint::BASE_POINT;
    let gs = g * s;
    let mut state = Sha512::new();
    state.update(&gr);
    state.update(public_key);
    state.update(message);
    let h = Scalar::from(state.finalize());
    let s2 = r + h * a;
    let verified = (gs == s2) as u64;
    (verified & valid_a & valid_r) == 1
}

fn expand(private_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let digest = sha512(private_key);
    let mut a = [0u8; 32];
    let mut prefix = [0u8; 32];
    a.copy_from_slice(&digest[0..32]);
    prefix.copy_from_slice(&digest[32..64]);
    clamp(&mut a);
    (a, prefix)
}

#[derive(Clone, Copy)]
struct EdwardsPoint {
    x: Curve25519,
    y: Curve25519,
    t: Curve25519,
    z: Curve25519,
}

impl EdwardsPoint {
    const BASE_POINT: Self = Self {
        x: Curve25519([
            1738742601995546,
            1146398526822698,
            2070867633025821,
            562264141797630,
            587772402128613,
        ]),
        y: Curve25519([
            1801439850948184,
            1351079888211148,
            450359962737049,
            900719925474099,
            1801439850948198,
        ]),
        z: Curve25519::ONE,
        t: Curve25519([
            1841354044333475,
            16398895984059,
            755974180946558,
            900171276175154,
            1821297809914039,
        ]),
    };
    const D: Curve25519 = Curve25519([
        929955233495203,
        466365720129213,
        1662059464998953,
        2033849074728123,
        1442794654840575,
    ]);
    const D2: Curve25519 = Curve25519([
        1859910466990425,
        932731440258426,
        1072319116312658,
        1815898335770999,
        633789495995903,
    ]);
    const IDENTITY: Self = Self {
        x: Curve25519::ZERO,
        y: Curve25519::ONE,
        z: Curve25519::ONE,
        t: Curve25519::ZERO,
    };

    fn decompress(scalar: &[u8; 32]) -> (Self, u64) {
        let sign = (scalar[31] >> 7) as u64;
        let mut bytes = *scalar;
        bytes[31] &= 127;
        let y = Curve25519::from(&bytes);
        let y2 = y.square();
        let u = y2 - Curve25519::ONE;
        let v = Self::D * y2 + Curve25519::ONE;
        let (mut x, mut valid) = u.sqrt(v);
        let is_zero = (x == Curve25519::ZERO) as u64;
        valid &= (is_zero & sign) ^ 1;
        let xs: [u8; 32] = x.into();
        let negate = (xs[0] as u64 & 1) ^ sign;
        x = Curve25519::select(&x, &x.neg(), negate);
        let point = Self {
            x,
            y,
            t: x * y,
            z: Curve25519::ONE,
        };
        (point, valid)
    }

    fn compress(self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x * zi;
        let y = self.y * zi;
        let xs: [u8; 32] = x.into();
        let mut ys: [u8; 32] = y.into();
        let sign = xs[0] & 1;
        ys[31] &= 127;
        ys[31] |= sign << 7;
        ys
    }

    fn mul(self, rhs: [u8; 32]) -> Self {
        let mut q = Self::IDENTITY;
        for i in (0..256).rev() {
            let bit = ((rhs[i / 8] >> (i % 8)) & 1) as u64;
            q = q.double();
            q = Self::select(&q, &q.add(self), bit);
        }
        q
    }

    fn add(self, rhs: Self) -> Self {
        let a = (self.y - self.x) * (rhs.y - rhs.x);
        let b = (self.y + self.x) * (rhs.y + rhs.x);
        let c = self.t * Self::D2 * rhs.t;
        let d = (self.z + self.z) * rhs.z;
        let e = b - a;
        let f = d - c;
        let g = d + c;
        let h = b + a;
        let x = e * f;
        let y = g * h;
        let t = e * h;
        let z = f * g;
        Self { x, y, t, z }
    }

    fn double(self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let z2 = self.z.square();
        let c = z2 + z2;
        let e = (self.x + self.y).square() - a - b;
        let g = b - a;
        let f = g - c;
        let h = Curve25519::ZERO - (a + b);
        let x = e * f;
        let y = g * h;
        let t = e * h;
        let z = f * g;
        Self { x, y, t, z }
    }

    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        Self {
            x: Curve25519::select(&a.x, &b.x, condition),
            y: Curve25519::select(&a.y, &b.y, condition),
            t: Curve25519::select(&a.t, &b.t, condition),
            z: Curve25519::select(&a.z, &b.z, condition),
        }
    }
}

impl PartialEq for EdwardsPoint {
    fn eq(&self, other: &Self) -> bool {
        (self.x * other.z) == (other.x * self.z)
    }
}

impl Eq for EdwardsPoint {}

impl Add for EdwardsPoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl Mul<[u8; 32]> for EdwardsPoint {
    type Output = Self;

    fn mul(self, rhs: [u8; 32]) -> Self::Output {
        self.mul(rhs)
    }
}

impl Mul<Scalar> for EdwardsPoint {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        self.mul(rhs.into())
    }
}

#[derive(Clone, Copy)]
struct Scalar([u64; 5]);

impl Scalar {
    const L: Self = Self([
        671914833335277,
        3916664325105025,
        1367801,
        0,
        17592186044416,
    ]);
    const LFACTOR: u64 = 0x51da312547e1b;
    const MASK: u64 = (1 << 52) - 1;
    const TOP_MASK: u64 = (1 << 48) - 1;
    const R: Self = Self([
        4302102966953709,
        1049714374468698,
        4503599278581019,
        4503599627370495,
        17592186044415,
    ]);
    const R2: Self = Self([
        2764609938444603,
        3768881411696287,
        1616719297148420,
        1087343033131391,
        10175238647962,
    ]);
    const ZERO: Self = Self([0; 5]);

    fn add(self, rhs: Self) -> Self {
        let mut s = Self::ZERO;
        s[0] = self[0] + rhs[0];
        s[1] = self[1] + rhs[1];
        s[2] = self[2] + rhs[2];
        s[3] = self[3] + rhs[3];
        s[4] = self[4] + rhs[4];
        s[1] += s[0] >> 52;
        s[2] += s[1] >> 52;
        s[3] += s[2] >> 52;
        s[4] += s[3] >> 52;
        s.mask();
        s.reduce();
        s
    }

    fn mask(&mut self) {
        self[0] &= Self::MASK;
        self[1] &= Self::MASK;
        self[2] &= Self::MASK;
        self[3] &= Self::MASK;
        self[4] &= Self::MASK;
    }

    fn montgomery_mul(self, rhs: Self) -> Self {
        fn m(x: u64, y: u64) -> u128 {
            (x as u128) * (y as u128)
        }
        let mut t = [0u128; 10];
        t[0] = m(self[0], rhs[0]);
        t[1] = m(self[0], rhs[1]) + m(self[1], rhs[0]);
        t[2] = m(self[0], rhs[2]) + m(self[1], rhs[1]) + m(self[2], rhs[0]);
        t[3] = m(self[0], rhs[3]) + m(self[1], rhs[2]) + m(self[2], rhs[1]) + m(self[3], rhs[0]);
        t[4] = m(self[0], rhs[4])
            + m(self[1], rhs[3])
            + m(self[2], rhs[2])
            + m(self[3], rhs[1])
            + m(self[4], rhs[0]);
        t[5] = m(self[1], rhs[4]) + m(self[2], rhs[3]) + m(self[3], rhs[2]) + m(self[4], rhs[1]);
        t[6] = m(self[2], rhs[4]) + m(self[3], rhs[3]) + m(self[4], rhs[2]);
        t[7] = m(self[3], rhs[4]) + m(self[4], rhs[3]);
        t[8] = m(self[4], rhs[4]);
        Self::round(&mut t, 0);
        Self::round(&mut t, 1);
        Self::round(&mut t, 2);
        Self::round(&mut t, 3);
        Self::round(&mut t, 4);
        t[6] += t[5] >> 52;
        t[7] += t[6] >> 52;
        t[8] += t[7] >> 52;
        t[9] += t[8] >> 52;
        let mut s = Self([
            t[5] as u64,
            t[6] as u64,
            t[7] as u64,
            t[8] as u64,
            t[9] as u64,
        ]);
        s.mask();
        s.reduce();
        s
    }

    fn round(t: &mut [u128; 10], i: usize) {
        let x = ((t[i] as u64).wrapping_mul(Self::LFACTOR) & Self::MASK) as u128;
        t[i] += x * Self::L[0] as u128;
        t[i + 1] += x * Self::L[1] as u128;
        t[i + 2] += x * Self::L[2] as u128;
        t[i + 4] += x * Self::L[4] as u128;
        t[i + 1] += t[i] >> 52;
    }

    fn reduce(&mut self) {
        let mut diff = Self::ZERO;
        let mut borrow = 0u64;
        for i in 0..5 {
            let (d1, b1) = self[i].overflowing_sub(Self::L[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            diff[i] = d2 & Self::MASK;
            borrow = (b1 | b2) as u64;
        }
        *self = Self::select(&diff, &self, borrow);
    }

    fn select(a: &Self, b: &Self, condition: u64) -> Self {
        let mask = ((condition != 0) as u64).wrapping_neg();
        Self([
            a[0] & !mask | b[0] & mask,
            a[1] & !mask | b[1] & mask,
            a[2] & !mask | b[2] & mask,
            a[3] & !mask | b[3] & mask,
            a[4] & !mask | b[4] & mask,
        ])
    }
}

impl Index<usize> for Scalar {
    type Output = u64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Scalar {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let ar = self.montgomery_mul(Self::R2);
        ar.montgomery_mul(rhs)
    }
}

impl Mul<[u8; 32]> for Scalar {
    type Output = Self;

    fn mul(self, rhs: [u8; 32]) -> Self::Output {
        self.mul(Self::from(rhs))
    }
}

impl Mul<EdwardsPoint> for Scalar {
    type Output = EdwardsPoint;

    fn mul(self, rhs: EdwardsPoint) -> Self::Output {
        rhs.mul(self.into())
    }
}

impl From<[u8; 32]> for Scalar {
    fn from(value: [u8; 32]) -> Self {
        let words = [
            u64::from_le_bytes(value[0..8].try_into().unwrap()),
            u64::from_le_bytes(value[8..16].try_into().unwrap()),
            u64::from_le_bytes(value[16..24].try_into().unwrap()),
            u64::from_le_bytes(value[24..32].try_into().unwrap()),
        ];
        let mut s = Self::ZERO;
        s[0] = words[0] & Self::MASK;
        s[1] = ((words[0] >> 52) | (words[1] << 12)) & Self::MASK;
        s[2] = ((words[1] >> 40) | (words[2] << 24)) & Self::MASK;
        s[3] = ((words[2] >> 28) | (words[3] << 36)) & Self::MASK;
        s[4] = (words[3] >> 16) & Self::TOP_MASK;
        s
    }
}

impl From<[u8; 64]> for Scalar {
    fn from(value: [u8; 64]) -> Self {
        let words = [
            u64::from_le_bytes(value[0..8].try_into().unwrap()),
            u64::from_le_bytes(value[8..16].try_into().unwrap()),
            u64::from_le_bytes(value[16..24].try_into().unwrap()),
            u64::from_le_bytes(value[24..32].try_into().unwrap()),
            u64::from_le_bytes(value[32..40].try_into().unwrap()),
            u64::from_le_bytes(value[40..48].try_into().unwrap()),
            u64::from_le_bytes(value[48..56].try_into().unwrap()),
            u64::from_le_bytes(value[56..64].try_into().unwrap()),
        ];
        let mut lo = Self::ZERO;
        let mut hi = Self::ZERO;
        lo[0] = words[0] & Self::MASK;
        lo[1] = ((words[0] >> 52) | (words[1] << 12)) & Self::MASK;
        lo[2] = ((words[1] >> 40) | (words[2] << 24)) & Self::MASK;
        lo[3] = ((words[2] >> 28) | (words[3] << 36)) & Self::MASK;
        lo[4] = ((words[3] >> 16) | (words[4] << 48)) & Self::MASK;
        hi[0] = (words[4] >> 4) & Self::MASK;
        hi[1] = ((words[4] >> 56) | (words[5] << 8)) & Self::MASK;
        hi[2] = ((words[5] >> 44) | (words[6] << 20)) & Self::MASK;
        hi[3] = ((words[6] >> 32) | (words[7] << 32)) & Self::MASK;
        hi[4] = words[7] >> 20;
        lo = lo.montgomery_mul(Self::R);
        hi = hi.montgomery_mul(Self::R2);
        hi + lo
    }
}

impl From<Scalar> for [u8; 32] {
    fn from(value: Scalar) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = value[0] as u8;
        bytes[1] = (value[0] >> 8) as u8;
        bytes[2] = (value[0] >> 16) as u8;
        bytes[3] = (value[0] >> 24) as u8;
        bytes[4] = (value[0] >> 32) as u8;
        bytes[5] = (value[0] >> 40) as u8;
        bytes[6] = ((value[0] >> 48) | (value[1] << 4)) as u8;
        bytes[7] = (value[1] >> 4) as u8;
        bytes[8] = (value[1] >> 12) as u8;
        bytes[9] = (value[1] >> 20) as u8;
        bytes[10] = (value[1] >> 28) as u8;
        bytes[11] = (value[1] >> 36) as u8;
        bytes[12] = (value[1] >> 44) as u8;
        bytes[13] = value[2] as u8;
        bytes[14] = (value[2] >> 8) as u8;
        bytes[15] = (value[2] >> 16) as u8;
        bytes[16] = (value[2] >> 24) as u8;
        bytes[17] = (value[2] >> 32) as u8;
        bytes[18] = (value[2] >> 40) as u8;
        bytes[19] = ((value[2] >> 48) | (value[3] << 4)) as u8;
        bytes[20] = (value[3] >> 4) as u8;
        bytes[21] = (value[3] >> 12) as u8;
        bytes[22] = (value[3] >> 20) as u8;
        bytes[23] = (value[3] >> 28) as u8;
        bytes[24] = (value[3] >> 36) as u8;
        bytes[25] = (value[3] >> 44) as u8;
        bytes[26] = value[4] as u8;
        bytes[27] = (value[4] >> 8) as u8;
        bytes[28] = (value[4] >> 16) as u8;
        bytes[29] = (value[4] >> 24) as u8;
        bytes[30] = (value[4] >> 32) as u8;
        bytes[31] = (value[4] >> 40) as u8;
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_tc1() {
        let private_key = [
            157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73, 197,
            105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
        ];
        let public_key_ref = [
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ];
        let message = [];
        let signature_ref = [
            229, 86, 67, 0, 195, 96, 172, 114, 144, 134, 226, 204, 128, 110, 130, 138, 132, 135,
            127, 30, 184, 229, 217, 116, 216, 115, 224, 101, 34, 73, 1, 85, 95, 184, 130, 21, 144,
            163, 59, 172, 198, 30, 57, 112, 28, 249, 180, 107, 210, 91, 245, 240, 89, 91, 190, 36,
            101, 81, 65, 67, 142, 122, 16, 11,
        ];
        let public_key = ed25519_public_key(&private_key);
        assert_eq!(public_key, public_key_ref);
        let signature = ed25519_sign(&private_key, &message);
        assert_eq!(signature, signature_ref);
        let verified = ed25519_verify(&message, &public_key, &signature);
        assert!(verified);
    }

    #[test]
    fn test_ed25519_tc2() {
        let private_key = [
            76, 205, 8, 155, 40, 255, 150, 218, 157, 182, 195, 70, 236, 17, 78, 15, 91, 138, 49,
            159, 53, 171, 166, 36, 218, 140, 246, 237, 79, 184, 166, 251,
        ];
        let public_key_ref = [
            61, 64, 23, 195, 232, 67, 137, 90, 146, 183, 10, 167, 77, 27, 126, 188, 156, 152, 44,
            207, 46, 196, 150, 140, 192, 205, 85, 241, 42, 244, 102, 12,
        ];
        let message = [114];
        let signature_ref = [
            146, 160, 9, 169, 240, 212, 202, 184, 114, 14, 130, 11, 95, 100, 37, 64, 162, 178, 123,
            84, 22, 80, 63, 143, 179, 118, 34, 35, 235, 219, 105, 218, 8, 90, 193, 228, 62, 21,
            153, 110, 69, 143, 54, 19, 208, 241, 29, 140, 56, 123, 46, 174, 180, 48, 42, 238, 176,
            13, 41, 22, 18, 187, 12, 0,
        ];
        let public_key = ed25519_public_key(&private_key);
        assert_eq!(public_key, public_key_ref);
        let signature = ed25519_sign(&private_key, &message);
        assert_eq!(signature, signature_ref);
        let verified = ed25519_verify(&message, &public_key, &signature);
        assert!(verified);
    }

    #[test]
    fn test_ed25519_tc3() {
        let private_key = [
            197, 170, 141, 244, 63, 159, 131, 123, 237, 183, 68, 47, 49, 220, 183, 177, 102, 211,
            133, 53, 7, 111, 9, 75, 133, 206, 58, 46, 11, 68, 88, 247,
        ];
        let public_key_ref = [
            252, 81, 205, 142, 98, 24, 161, 163, 141, 164, 126, 208, 2, 48, 240, 88, 8, 22, 237,
            19, 186, 51, 3, 172, 93, 235, 145, 21, 72, 144, 128, 37,
        ];
        let message = [175, 130];
        let signature_ref = [
            98, 145, 214, 87, 222, 236, 36, 2, 72, 39, 230, 156, 58, 190, 1, 163, 12, 229, 72, 162,
            132, 116, 58, 68, 94, 54, 128, 215, 219, 90, 195, 172, 24, 255, 155, 83, 141, 22, 242,
            144, 174, 103, 247, 96, 152, 77, 198, 89, 74, 124, 21, 233, 113, 110, 210, 141, 192,
            39, 190, 206, 234, 30, 196, 10,
        ];
        let public_key = ed25519_public_key(&private_key);
        assert_eq!(public_key, public_key_ref);
        let signature = ed25519_sign(&private_key, &message);
        assert_eq!(signature, signature_ref);
        let verified = ed25519_verify(&message, &public_key, &signature);
        assert!(verified);
    }

    #[test]
    fn test_ed25519_tc4() {
        let private_key = [
            245, 229, 118, 124, 241, 83, 49, 149, 23, 99, 15, 34, 104, 118, 184, 108, 129, 96, 204,
            88, 59, 192, 19, 116, 76, 107, 242, 85, 245, 204, 14, 229,
        ];
        let public_key_ref = [
            39, 129, 23, 252, 20, 76, 114, 52, 15, 103, 208, 242, 49, 110, 131, 134, 206, 255, 191,
            43, 36, 40, 201, 197, 31, 239, 124, 89, 127, 29, 66, 110,
        ];
        let message = [
            8, 184, 178, 183, 51, 66, 66, 67, 118, 15, 228, 38, 164, 181, 73, 8, 99, 33, 16, 166,
            108, 47, 101, 145, 234, 189, 51, 69, 227, 228, 235, 152, 250, 110, 38, 75, 240, 158,
            254, 18, 238, 80, 248, 245, 78, 159, 119, 177, 227, 85, 246, 197, 5, 68, 226, 63, 177,
            67, 61, 223, 115, 190, 132, 216, 121, 222, 124, 0, 70, 220, 73, 150, 217, 231, 115,
            244, 188, 158, 254, 87, 56, 130, 154, 219, 38, 200, 27, 55, 201, 58, 27, 39, 11, 32,
            50, 157, 101, 134, 117, 252, 110, 165, 52, 224, 129, 10, 68, 50, 130, 107, 245, 140,
            148, 30, 251, 101, 213, 122, 51, 139, 189, 46, 38, 100, 15, 137, 255, 188, 26, 133,
            142, 252, 184, 85, 14, 227, 165, 225, 153, 139, 209, 119, 233, 58, 115, 99, 195, 68,
            254, 107, 25, 158, 229, 208, 46, 130, 213, 34, 196, 254, 186, 21, 69, 47, 128, 40, 138,
            130, 26, 87, 145, 22, 236, 109, 173, 43, 59, 49, 13, 169, 3, 64, 26, 166, 33, 0, 171,
            93, 26, 54, 85, 62, 6, 32, 59, 51, 137, 12, 201, 184, 50, 247, 158, 248, 5, 96, 204,
            185, 163, 156, 231, 103, 150, 126, 214, 40, 198, 173, 87, 60, 177, 22, 219, 239, 239,
            215, 84, 153, 218, 150, 189, 104, 168, 169, 123, 146, 138, 139, 188, 16, 59, 102, 33,
            252, 222, 43, 236, 161, 35, 29, 32, 107, 230, 205, 158, 199, 175, 246, 246, 201, 79,
            205, 114, 4, 237, 52, 85, 198, 140, 131, 244, 164, 29, 164, 175, 43, 116, 239, 92, 83,
            241, 216, 172, 112, 189, 203, 126, 209, 133, 206, 129, 189, 132, 53, 157, 68, 37, 77,
            149, 98, 158, 152, 85, 169, 74, 124, 25, 88, 209, 248, 173, 165, 208, 83, 46, 216, 165,
            170, 63, 178, 209, 123, 167, 14, 182, 36, 142, 89, 78, 26, 34, 151, 172, 187, 179, 157,
            80, 47, 26, 140, 110, 182, 241, 206, 34, 179, 222, 26, 31, 64, 204, 36, 85, 65, 25,
            168, 49, 169, 170, 214, 7, 156, 173, 136, 66, 93, 230, 189, 225, 169, 24, 126, 187, 96,
            146, 207, 103, 191, 43, 19, 253, 101, 242, 112, 136, 215, 139, 126, 136, 60, 135, 89,
            210, 196, 245, 198, 90, 219, 117, 83, 135, 138, 213, 117, 249, 250, 216, 120, 232, 10,
            12, 155, 166, 59, 203, 204, 39, 50, 230, 148, 133, 187, 201, 201, 11, 251, 214, 36,
            129, 217, 8, 155, 236, 207, 128, 207, 226, 223, 22, 162, 207, 101, 189, 146, 221, 89,
            123, 7, 7, 224, 145, 122, 244, 139, 187, 117, 254, 212, 19, 210, 56, 245, 85, 90, 122,
            86, 157, 128, 195, 65, 74, 141, 8, 89, 220, 101, 164, 97, 40, 186, 178, 122, 248, 122,
            113, 49, 79, 49, 140, 120, 43, 35, 235, 254, 128, 139, 130, 176, 206, 38, 64, 29, 46,
            34, 240, 77, 131, 209, 37, 93, 197, 26, 221, 211, 183, 90, 43, 26, 224, 120, 69, 4,
            223, 84, 58, 248, 150, 155, 227, 234, 112, 130, 255, 127, 201, 136, 140, 20, 77, 162,
            175, 88, 66, 158, 201, 96, 49, 219, 202, 211, 218, 217, 175, 13, 203, 170, 175, 38,
            140, 184, 252, 255, 234, 217, 79, 60, 124, 164, 149, 224, 86, 169, 180, 122, 205, 183,
            81, 251, 115, 230, 102, 198, 198, 85, 173, 232, 41, 114, 151, 208, 122, 209, 186, 94,
            67, 241, 188, 163, 35, 1, 101, 19, 57, 226, 41, 4, 204, 140, 66, 245, 140, 48, 192, 74,
            175, 219, 3, 141, 218, 8, 71, 221, 152, 141, 205, 166, 243, 191, 209, 92, 75, 76, 69,
            37, 0, 74, 160, 110, 239, 248, 202, 97, 120, 58, 172, 236, 87, 251, 61, 31, 146, 176,
            254, 47, 209, 168, 95, 103, 36, 81, 123, 101, 230, 20, 173, 104, 8, 214, 246, 238, 52,
            223, 247, 49, 15, 220, 130, 174, 191, 217, 4, 176, 30, 29, 197, 75, 41, 39, 9, 75, 45,
            182, 141, 111, 144, 59, 104, 64, 26, 222, 191, 90, 126, 8, 215, 143, 244, 239, 93, 99,
            101, 58, 101, 4, 12, 249, 191, 212, 172, 167, 152, 74, 116, 211, 113, 69, 152, 103,
            128, 252, 11, 22, 172, 69, 22, 73, 222, 97, 136, 167, 219, 223, 25, 31, 100, 181, 252,
            94, 42, 180, 123, 87, 247, 247, 39, 108, 212, 25, 193, 122, 60, 168, 225, 185, 57, 174,
            73, 228, 136, 172, 186, 107, 150, 86, 16, 181, 72, 1, 9, 200, 177, 123, 128, 225, 183,
            183, 80, 223, 199, 89, 141, 93, 80, 17, 253, 45, 204, 86, 0, 163, 46, 245, 181, 42, 30,
            204, 130, 14, 48, 138, 163, 66, 114, 26, 172, 9, 67, 191, 102, 134, 182, 75, 37, 121,
            55, 101, 4, 204, 196, 147, 217, 126, 106, 237, 63, 176, 249, 205, 113, 164, 61, 212,
            151, 240, 31, 23, 192, 226, 203, 55, 151, 170, 42, 47, 37, 102, 86, 22, 142, 108, 73,
            106, 252, 95, 185, 50, 70, 246, 177, 17, 99, 152, 163, 70, 241, 166, 65, 243, 176, 65,
            233, 137, 247, 145, 79, 144, 204, 44, 127, 255, 53, 120, 118, 229, 6, 181, 13, 51, 75,
            167, 124, 34, 91, 195, 7, 186, 83, 113, 82, 243, 241, 97, 14, 78, 175, 229, 149, 246,
            217, 217, 13, 17, 250, 169, 51, 161, 94, 241, 54, 149, 70, 134, 138, 127, 58, 69, 169,
            103, 104, 212, 15, 217, 208, 52, 18, 192, 145, 198, 49, 92, 244, 253, 231, 203, 104,
            96, 105, 55, 56, 13, 178, 234, 170, 112, 123, 76, 65, 133, 195, 46, 221, 205, 211, 6,
            112, 94, 77, 193, 255, 200, 114, 238, 238, 71, 90, 100, 223, 172, 134, 171, 164, 28, 6,
            24, 152, 63, 135, 65, 197, 239, 104, 211, 161, 1, 232, 163, 184, 202, 198, 12, 144, 92,
            21, 252, 145, 8, 64, 185, 76, 0, 160, 185, 208,
        ];
        let signature_ref = [
            10, 171, 76, 144, 5, 1, 179, 226, 77, 124, 223, 70, 99, 50, 106, 58, 135, 223, 94, 72,
            67, 178, 203, 219, 103, 203, 246, 228, 96, 254, 195, 80, 170, 83, 113, 177, 80, 143,
            159, 69, 40, 236, 234, 35, 196, 54, 217, 75, 94, 143, 205, 79, 104, 30, 48, 166, 172,
            0, 169, 112, 74, 24, 138, 3,
        ];
        let public_key = ed25519_public_key(&private_key);
        assert_eq!(public_key, public_key_ref);
        let signature = ed25519_sign(&private_key, &message);
        assert_eq!(signature, signature_ref);
        let verified = ed25519_verify(&message, &public_key, &signature);
        assert!(verified);
    }

    #[test]
    fn test_ed25519_tc5() {
        let private_key = [
            131, 63, 230, 36, 9, 35, 123, 157, 98, 236, 119, 88, 117, 32, 145, 30, 154, 117, 156,
            236, 29, 25, 117, 91, 125, 169, 1, 185, 109, 202, 61, 66,
        ];
        let public_key_ref = [
            236, 23, 43, 147, 173, 94, 86, 59, 244, 147, 44, 112, 225, 36, 80, 52, 195, 84, 103,
            239, 46, 253, 77, 100, 235, 248, 25, 104, 52, 103, 226, 191,
        ];
        let message = [
            221, 175, 53, 161, 147, 97, 122, 186, 204, 65, 115, 73, 174, 32, 65, 49, 18, 230, 250,
            78, 137, 169, 126, 162, 10, 158, 238, 230, 75, 85, 211, 154, 33, 146, 153, 42, 39, 79,
            193, 168, 54, 186, 60, 35, 163, 254, 235, 189, 69, 77, 68, 35, 100, 60, 232, 14, 42,
            154, 201, 79, 165, 76, 164, 159,
        ];
        let signature_ref = [
            220, 42, 68, 89, 231, 54, 150, 51, 165, 43, 27, 242, 119, 131, 154, 0, 32, 16, 9, 163,
            239, 191, 62, 203, 105, 190, 162, 24, 108, 38, 181, 137, 9, 53, 31, 201, 172, 144, 179,
            236, 253, 251, 199, 198, 100, 49, 224, 48, 61, 202, 23, 156, 19, 138, 193, 122, 217,
            190, 241, 23, 115, 49, 167, 4,
        ];
        let public_key = ed25519_public_key(&private_key);
        assert_eq!(public_key, public_key_ref);
        let signature = ed25519_sign(&private_key, &message);
        assert_eq!(signature, signature_ref);
        let verified = ed25519_verify(&message, &public_key, &signature);
        assert!(verified);
    }
}
