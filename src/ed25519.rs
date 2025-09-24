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
    let g = EdwardsPoint::base_point();
    let (a, _) = expand(private_key);
    (g * a).compress()
}

pub fn ed25519_sign(private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let g = EdwardsPoint::base_point();
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
    let g = EdwardsPoint::base_point();
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
    const BASE_X: [u8; 32] = [
        26, 213, 37, 143, 96, 45, 86, 201, 178, 167, 37, 149, 96, 199, 44, 105, 92, 220, 214, 253,
        49, 226, 164, 192, 254, 83, 110, 205, 211, 54, 105, 33,
    ];
    const BASE_Y: [u8; 32] = [
        88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
        102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
    ];
    const D: [u8; 32] = [
        163, 120, 89, 19, 202, 77, 235, 117, 171, 216, 65, 65, 77, 10, 112, 0, 152, 232, 121, 119,
        121, 64, 199, 140, 115, 254, 111, 43, 238, 108, 3, 82,
    ];
    const D2: [u8; 32] = [
        89, 241, 178, 38, 148, 155, 214, 235, 86, 177, 131, 130, 154, 20, 224, 0, 48, 209, 243,
        238, 242, 128, 142, 25, 231, 252, 223, 86, 220, 217, 6, 36,
    ];

    fn base_point() -> Self {
        let x = Curve25519::from(&Self::BASE_X);
        let y = Curve25519::from(&Self::BASE_Y);
        let t = x * y;
        let z = Curve25519::one();
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

    fn decompress(scalar: &[u8; 32]) -> (Self, u64) {
        let sign = (scalar[31] >> 7) as u64;
        let mut bytes = *scalar;
        bytes[31] &= 127;
        let zero = Curve25519::zero();
        let one = Curve25519::one();
        let y = Curve25519::from(&bytes);
        let d = Curve25519::from(&Self::D);
        let y2 = y.square();
        let u = y2 - one;
        let v = d * y2 + one;
        let (mut x, mut valid) = u.sqrt(v);
        let is_zero = (x == zero) as u64;
        valid &= (is_zero & sign) ^ 1;
        let xs: [u8; 32] = x.into();
        let negate = (xs[0] as u64 & 1) ^ sign;
        x = Curve25519::select(&x, &x.neg(), negate);
        let t = x * y;
        (Self { x, y, t, z: one }, valid)
    }

    fn compress(self) -> [u8; 32] {
        let x = self.x / self.z;
        let y = self.y / self.z;
        let xs: [u8; 32] = x.into();
        let mut ys: [u8; 32] = y.into();
        let sign = xs[0] & 1;
        ys[31] &= 127;
        ys[31] |= sign << 7;
        ys
    }

    fn mul(self, rhs: [u8; 32]) -> Self {
        let mut q = EdwardsPoint {
            x: Curve25519::zero(),
            y: Curve25519::one(),
            z: Curve25519::one(),
            t: Curve25519::zero(),
        };
        for i in (0..256).rev() {
            let bit = ((rhs[i / 8] >> (i % 8)) & 1) as u64;
            q = q.double();
            q = Self::select(&q, &q.add(self), bit);
        }
        q
    }

    fn add(self, rhs: Self) -> Self {
        let d2 = Curve25519::from(&Self::D2);
        let a = (self.y - self.x) * (rhs.y - rhs.x);
        let b = (self.y + self.x) * (rhs.y + rhs.x);
        let c = self.t * d2 * rhs.t;
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
        let h = Curve25519::zero() - (a + b);
        let x = e * f;
        let y = g * h;
        let t = e * h;
        let z = f * g;
        Self { x, y, t, z }
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
struct Scalar([i64; 24]);

impl Scalar {
    const MASK: i64 = (1i64 << 21) - 1;

    fn zero() -> Self {
        Self([0; 24])
    }

    fn add(self, rhs: Self) -> Self {
        let mut r = Self::zero();
        r[0] = self[0] + rhs[0];
        r[1] = self[1] + rhs[1];
        r[2] = self[2] + rhs[2];
        r[3] = self[3] + rhs[3];
        r[4] = self[4] + rhs[4];
        r[5] = self[5] + rhs[5];
        r[6] = self[6] + rhs[6];
        r[7] = self[7] + rhs[7];
        r[8] = self[8] + rhs[8];
        r[9] = self[9] + rhs[9];
        r[10] = self[10] + rhs[10];
        r[11] = self[11] + rhs[11];
        r.reduce();
        r
    }

    fn mul(self, rhs: Self) -> Self {
        let mut r = Self::zero();
        r[0] += self[0] * rhs[0];
        r[1] += self[0] * rhs[1];
        r[1] += self[1] * rhs[0];
        r[2] += self[0] * rhs[2];
        r[2] += self[1] * rhs[1];
        r[2] += self[2] * rhs[0];
        r[3] += self[0] * rhs[3];
        r[3] += self[1] * rhs[2];
        r[3] += self[2] * rhs[1];
        r[3] += self[3] * rhs[0];
        r[4] += self[0] * rhs[4];
        r[4] += self[1] * rhs[3];
        r[4] += self[2] * rhs[2];
        r[4] += self[3] * rhs[1];
        r[4] += self[4] * rhs[0];
        r[5] += self[0] * rhs[5];
        r[5] += self[1] * rhs[4];
        r[5] += self[2] * rhs[3];
        r[5] += self[3] * rhs[2];
        r[5] += self[4] * rhs[1];
        r[5] += self[5] * rhs[0];
        r[6] += self[0] * rhs[6];
        r[6] += self[1] * rhs[5];
        r[6] += self[2] * rhs[4];
        r[6] += self[3] * rhs[3];
        r[6] += self[4] * rhs[2];
        r[6] += self[5] * rhs[1];
        r[6] += self[6] * rhs[0];
        r[7] += self[0] * rhs[7];
        r[7] += self[1] * rhs[6];
        r[7] += self[2] * rhs[5];
        r[7] += self[3] * rhs[4];
        r[7] += self[4] * rhs[3];
        r[7] += self[5] * rhs[2];
        r[7] += self[6] * rhs[1];
        r[7] += self[7] * rhs[0];
        r[8] += self[0] * rhs[8];
        r[8] += self[1] * rhs[7];
        r[8] += self[2] * rhs[6];
        r[8] += self[3] * rhs[5];
        r[8] += self[4] * rhs[4];
        r[8] += self[5] * rhs[3];
        r[8] += self[6] * rhs[2];
        r[8] += self[7] * rhs[1];
        r[8] += self[8] * rhs[0];
        r[9] += self[0] * rhs[9];
        r[9] += self[1] * rhs[8];
        r[9] += self[2] * rhs[7];
        r[9] += self[3] * rhs[6];
        r[9] += self[4] * rhs[5];
        r[9] += self[5] * rhs[4];
        r[9] += self[6] * rhs[3];
        r[9] += self[7] * rhs[2];
        r[9] += self[8] * rhs[1];
        r[9] += self[9] * rhs[0];
        r[10] += self[0] * rhs[10];
        r[10] += self[1] * rhs[9];
        r[10] += self[2] * rhs[8];
        r[10] += self[3] * rhs[7];
        r[10] += self[4] * rhs[6];
        r[10] += self[5] * rhs[5];
        r[10] += self[6] * rhs[4];
        r[10] += self[7] * rhs[3];
        r[10] += self[8] * rhs[2];
        r[10] += self[9] * rhs[1];
        r[10] += self[10] * rhs[0];
        r[11] += self[0] * rhs[11];
        r[11] += self[1] * rhs[10];
        r[11] += self[2] * rhs[9];
        r[11] += self[3] * rhs[8];
        r[11] += self[4] * rhs[7];
        r[11] += self[5] * rhs[6];
        r[11] += self[6] * rhs[5];
        r[11] += self[7] * rhs[4];
        r[11] += self[8] * rhs[3];
        r[11] += self[9] * rhs[2];
        r[11] += self[10] * rhs[1];
        r[11] += self[11] * rhs[0];
        r[12] += self[1] * rhs[11];
        r[12] += self[2] * rhs[10];
        r[12] += self[3] * rhs[9];
        r[12] += self[4] * rhs[8];
        r[12] += self[5] * rhs[7];
        r[12] += self[6] * rhs[6];
        r[12] += self[7] * rhs[5];
        r[12] += self[8] * rhs[4];
        r[12] += self[9] * rhs[3];
        r[12] += self[10] * rhs[2];
        r[12] += self[11] * rhs[1];
        r[13] += self[2] * rhs[11];
        r[13] += self[3] * rhs[10];
        r[13] += self[4] * rhs[9];
        r[13] += self[5] * rhs[8];
        r[13] += self[6] * rhs[7];
        r[13] += self[7] * rhs[6];
        r[13] += self[8] * rhs[5];
        r[13] += self[9] * rhs[4];
        r[13] += self[10] * rhs[3];
        r[13] += self[11] * rhs[2];
        r[14] += self[3] * rhs[11];
        r[14] += self[4] * rhs[10];
        r[14] += self[5] * rhs[9];
        r[14] += self[6] * rhs[8];
        r[14] += self[7] * rhs[7];
        r[14] += self[8] * rhs[6];
        r[14] += self[9] * rhs[5];
        r[14] += self[10] * rhs[4];
        r[14] += self[11] * rhs[3];
        r[15] += self[4] * rhs[11];
        r[15] += self[5] * rhs[10];
        r[15] += self[6] * rhs[9];
        r[15] += self[7] * rhs[8];
        r[15] += self[8] * rhs[7];
        r[15] += self[9] * rhs[6];
        r[15] += self[10] * rhs[5];
        r[15] += self[11] * rhs[4];
        r[16] += self[5] * rhs[11];
        r[16] += self[6] * rhs[10];
        r[16] += self[7] * rhs[9];
        r[16] += self[8] * rhs[8];
        r[16] += self[9] * rhs[7];
        r[16] += self[10] * rhs[6];
        r[16] += self[11] * rhs[5];
        r[17] += self[6] * rhs[11];
        r[17] += self[7] * rhs[10];
        r[17] += self[8] * rhs[9];
        r[17] += self[9] * rhs[8];
        r[17] += self[10] * rhs[7];
        r[17] += self[11] * rhs[6];
        r[18] += self[7] * rhs[11];
        r[18] += self[8] * rhs[10];
        r[18] += self[9] * rhs[9];
        r[18] += self[10] * rhs[8];
        r[18] += self[11] * rhs[7];
        r[19] += self[8] * rhs[11];
        r[19] += self[9] * rhs[10];
        r[19] += self[10] * rhs[9];
        r[19] += self[11] * rhs[8];
        r[20] += self[9] * rhs[11];
        r[20] += self[10] * rhs[10];
        r[20] += self[11] * rhs[9];
        r[21] += self[10] * rhs[11];
        r[21] += self[11] * rhs[10];
        r[22] += self[11] * rhs[11];
        r.carry_balanced(0);
        r.carry_balanced(2);
        r.carry_balanced(4);
        r.carry_balanced(6);
        r.carry_balanced(8);
        r.carry_balanced(10);
        r.carry_balanced(12);
        r.carry_balanced(14);
        r.carry_balanced(16);
        r.carry_balanced(18);
        r.carry_balanced(20);
        r.carry_balanced(22);
        r.carry_balanced(1);
        r.carry_balanced(3);
        r.carry_balanced(5);
        r.carry_balanced(7);
        r.carry_balanced(9);
        r.carry_balanced(11);
        r.carry_balanced(13);
        r.carry_balanced(15);
        r.carry_balanced(17);
        r.carry_balanced(19);
        r.carry_balanced(21);
        r.reduce();
        r
    }

    fn reduce(&mut self) {
        self.fold(23);
        self.fold(22);
        self.fold(21);
        self.fold(20);
        self.fold(19);
        self.fold(18);
        self.carry_balanced(6);
        self.carry_balanced(8);
        self.carry_balanced(10);
        self.carry_balanced(12);
        self.carry_balanced(14);
        self.carry_balanced(16);
        self.carry_balanced(7);
        self.carry_balanced(9);
        self.carry_balanced(11);
        self.carry_balanced(13);
        self.carry_balanced(15);
        self.fold(17);
        self.fold(16);
        self.fold(15);
        self.fold(14);
        self.fold(13);
        self.fold(12);
        self.carry_balanced(0);
        self.carry_balanced(2);
        self.carry_balanced(4);
        self.carry_balanced(6);
        self.carry_balanced(8);
        self.carry_balanced(10);
        self.carry_balanced(1);
        self.carry_balanced(3);
        self.carry_balanced(5);
        self.carry_balanced(7);
        self.carry_balanced(9);
        self.carry_balanced(11);
        self.fold(12);
    }

    fn canonical(&mut self) {
        self.carry(0);
        self.carry(1);
        self.carry(2);
        self.carry(3);
        self.carry(4);
        self.carry(5);
        self.carry(6);
        self.carry(7);
        self.carry(8);
        self.carry(9);
        self.carry(10);
        self.carry(11);
        self.fold(12);
        self.carry(0);
        self.carry(1);
        self.carry(2);
        self.carry(3);
        self.carry(4);
        self.carry(5);
        self.carry(6);
        self.carry(7);
        self.carry(8);
        self.carry(9);
        self.carry(10);
    }

    fn fold(&mut self, i: usize) {
        self[i - 12] += self[i] * 666643;
        self[i - 11] += self[i] * 470296;
        self[i - 10] += self[i] * 654183;
        self[i - 9] -= self[i] * 997805;
        self[i - 8] += self[i] * 136657;
        self[i - 7] -= self[i] * 683901;
        self[i] = 0;
    }

    fn carry_balanced(&mut self, i: usize) {
        let carry = (self[i] + (1 << 20)) >> 21;
        self[i + 1] += carry;
        self[i] -= carry << 21;
    }

    fn carry(&mut self, i: usize) {
        let carry = self[i] >> 21;
        self[i + 1] += carry;
        self[i] -= carry << 21;
    }
}

impl Index<usize> for Scalar {
    type Output = i64;

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
        self.mul(rhs)
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
        let mut r = Self::zero();
        r[0] = load3(&value, 0) & Self::MASK;
        r[1] = (load4(&value, 2) >> 5) & Self::MASK;
        r[2] = (load3(&value, 5) >> 2) & Self::MASK;
        r[3] = (load4(&value, 7) >> 7) & Self::MASK;
        r[4] = (load4(&value, 10) >> 4) & Self::MASK;
        r[5] = (load3(&value, 13) >> 1) & Self::MASK;
        r[6] = (load4(&value, 15) >> 6) & Self::MASK;
        r[7] = (load3(&value, 18) >> 3) & Self::MASK;
        r[8] = load3(&value, 21) & Self::MASK;
        r[9] = (load4(&value, 23) >> 5) & Self::MASK;
        r[10] = (load3(&value, 26) >> 2) & Self::MASK;
        r[11] = load4(&value, 28) >> 7;
        r.reduce();
        r
    }
}

fn load3(s: &[u8], i: usize) -> i64 {
    (s[i] as i64) | ((s[i + 1] as i64) << 8) | ((s[i + 2] as i64) << 16)
}

fn load4(s: &[u8], i: usize) -> i64 {
    (s[i] as i64) | ((s[i + 1] as i64) << 8) | ((s[i + 2] as i64) << 16) | ((s[i + 3] as i64) << 24)
}

impl From<[u8; 64]> for Scalar {
    fn from(value: [u8; 64]) -> Self {
        let mut r = Self::zero();
        r[0] = load3(&value, 0) & Self::MASK;
        r[1] = (load4(&value, 2) >> 5) & Self::MASK;
        r[2] = (load3(&value, 5) >> 2) & Self::MASK;
        r[3] = (load4(&value, 7) >> 7) & Self::MASK;
        r[4] = (load4(&value, 10) >> 4) & Self::MASK;
        r[5] = (load3(&value, 13) >> 1) & Self::MASK;
        r[6] = (load4(&value, 15) >> 6) & Self::MASK;
        r[7] = (load3(&value, 18) >> 3) & Self::MASK;
        r[8] = load3(&value, 21) & Self::MASK;
        r[9] = (load4(&value, 23) >> 5) & Self::MASK;
        r[10] = (load3(&value, 26) >> 2) & Self::MASK;
        r[11] = (load4(&value, 28) >> 7) & Self::MASK;
        r[12] = (load4(&value, 31) >> 4) & Self::MASK;
        r[13] = (load3(&value, 34) >> 1) & Self::MASK;
        r[14] = (load4(&value, 36) >> 6) & Self::MASK;
        r[15] = (load3(&value, 39) >> 3) & Self::MASK;
        r[16] = load3(&value, 42) & Self::MASK;
        r[17] = (load4(&value, 44) >> 5) & Self::MASK;
        r[18] = (load3(&value, 47) >> 2) & Self::MASK;
        r[19] = (load4(&value, 49) >> 7) & Self::MASK;
        r[20] = (load4(&value, 52) >> 4) & Self::MASK;
        r[21] = (load3(&value, 55) >> 1) & Self::MASK;
        r[22] = (load4(&value, 57) >> 6) & Self::MASK;
        r[23] = load4(&value, 60) >> 3;
        r.reduce();
        r
    }
}

impl From<Scalar> for [u8; 32] {
    fn from(value: Scalar) -> Self {
        let r: [u32; 8] = value.into();
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&r[0].to_le_bytes());
        bytes[4..8].copy_from_slice(&r[1].to_le_bytes());
        bytes[8..12].copy_from_slice(&r[2].to_le_bytes());
        bytes[12..16].copy_from_slice(&r[3].to_le_bytes());
        bytes[16..20].copy_from_slice(&r[4].to_le_bytes());
        bytes[20..24].copy_from_slice(&r[5].to_le_bytes());
        bytes[24..28].copy_from_slice(&r[6].to_le_bytes());
        bytes[28..32].copy_from_slice(&r[7].to_le_bytes());
        bytes
    }
}

impl From<Scalar> for [u32; 8] {
    fn from(mut value: Scalar) -> Self {
        value.canonical();
        [
            ((value[0]) | (value[1] << 21)) as u32,
            ((value[1] >> 11) | (value[2] << 10) | (value[3] << 31)) as u32,
            ((value[3] >> 1) | (value[4] << 20)) as u32,
            ((value[4] >> 12) | (value[5] << 9) | (value[6] << 30)) as u32,
            ((value[6] >> 2) | (value[7] << 19)) as u32,
            ((value[7] >> 13) | (value[8] << 8) | (value[9] << 29)) as u32,
            ((value[9] >> 3) | (value[10] << 18)) as u32,
            ((value[10] >> 14) | (value[11] << 7)) as u32,
        ]
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
