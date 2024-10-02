use blake2::Blake2b512;
use sha2::Digest;

trait HashAlgorithm {
    fn calculate_digest(digest: &mut [u8], message: &[u8]);
}

pub const BLAKE2B_DIGEST_SIZE: usize = 64;
pub const BLAKE3_DIGEST_SIZE: usize = 32;
pub const SHA512_DIGEST_SIZE: usize = 64;

pub type Blake2bDigest = [u8; BLAKE2B_DIGEST_SIZE];
pub type Blake3Digest = [u8; BLAKE3_DIGEST_SIZE];
pub type Sha512Digest = [u8; SHA512_DIGEST_SIZE];

struct Blake2b;

impl HashAlgorithm for Blake2b {
    fn calculate_digest(digest: &mut [u8], message: &[u8]) {
        let mut hasher = Blake2b512::new();
        hasher.update(message);
        digest.copy_from_slice(hasher.finalize().as_slice());
    }
}

struct Blake3;

impl HashAlgorithm for Blake3 {
    fn calculate_digest(digest: &mut [u8], message: &[u8]) {
        digest.copy_from_slice(blake3::hash(message).as_bytes());
    }
}

struct Sha512;

impl HashAlgorithm for Sha512 {
    fn calculate_digest(digest: &mut [u8], message: &[u8]) {
        let mut hasher = sha2::Sha512::new();
        hasher.update(message);
        digest.copy_from_slice(hasher.finalize().as_slice());
    }
}

fn hash<H: HashAlgorithm>(a: &mut [u8], b: &mut [u8], message: &[u8], iterations: Option<u32>) {
    let iterations = match iterations {
        Some(i) => {
            if i == 0 {
                1
            } else {
                i
            }
        }
        None => 1,
    };
    H::calculate_digest(a, message);
    for _ in 1..iterations {
        H::calculate_digest(b, a);
        a.copy_from_slice(b);
    }
}

pub fn blake2b(message: &[u8], iterations: Option<u32>) -> Blake2bDigest {
    let mut a = [0; BLAKE2B_DIGEST_SIZE];
    let mut b = [0; BLAKE2B_DIGEST_SIZE];
    hash::<Blake2b>(&mut a, &mut b, message, iterations);
    a
}

pub fn blake3(message: &[u8], iterations: Option<u32>) -> Blake3Digest {
    let mut a = [0; BLAKE3_DIGEST_SIZE];
    let mut b = [0; BLAKE3_DIGEST_SIZE];
    hash::<Blake3>(&mut a, &mut b, message, iterations);
    a
}

pub fn sha512(message: &[u8], iterations: Option<u32>) -> Sha512Digest {
    let mut a = [0; SHA512_DIGEST_SIZE];
    let mut b = [0; SHA512_DIGEST_SIZE];
    hash::<Sha512>(&mut a, &mut b, message, iterations);
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_blake2b() {
        let message = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        let digest: Blake2bDigest = [
            67, 134, 160, 138, 38, 81, 17, 201, 137, 111, 86, 69, 110, 44, 182, 26, 100, 35, 145,
            21, 196, 120, 76, 244, 56, 227, 108, 200, 81, 34, 25, 114, 218, 63, 176, 17, 95, 115,
            205, 2, 72, 98, 84, 0, 31, 135, 138, 177, 253, 18, 106, 172, 105, 132, 78, 241, 193,
            202, 21, 35, 121, 208, 169, 189,
        ];
        assert_eq!(blake2b(&message, None), digest);
        assert_eq!(blake2b(&message, Some(1)), digest);
    }

    #[test]
    fn test_blake2b_iterated() {
        let message = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        let digest: Blake2bDigest = [
            165, 34, 42, 151, 213, 48, 192, 184, 236, 68, 32, 92, 134, 69, 116, 201, 216, 176, 198,
            69, 247, 183, 71, 209, 62, 237, 92, 205, 127, 80, 67, 76, 77, 68, 41, 156, 124, 242,
            193, 50, 113, 106, 77, 72, 213, 109, 152, 34, 164, 26, 112, 6, 94, 255, 25, 175, 162,
            76, 14, 157, 240, 122, 113, 141,
        ];
        assert_eq!(blake2b(&message, Some(5)), digest);
    }

    #[test]
    fn test_blake3() {
        let message = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        let digest: Blake3Digest = [
            65, 248, 57, 65, 17, 235, 113, 58, 34, 22, 92, 70, 201, 10, 184, 240, 253, 147, 153,
            201, 32, 40, 253, 109, 40, 137, 68, 178, 63, 245, 191, 118,
        ];
        assert_eq!(blake3(&message, None), digest);
        assert_eq!(blake3(&message, Some(1)), digest);
    }

    #[test]
    fn test_blake3_iterated() {
        let message = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        let digest: Blake3Digest = [
            73, 86, 44, 152, 53, 8, 142, 148, 150, 47, 215, 36, 45, 218, 92, 255, 55, 19, 171, 7,
            186, 35, 106, 200, 76, 20, 156, 123, 76, 238, 185, 58,
        ];
        assert_eq!(blake3(&message, Some(5)), digest);
    }

    #[test]
    fn test_sha512() {
        let message = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        let digest: Sha512Digest = [
            44, 116, 253, 23, 237, 175, 216, 14, 132, 71, 176, 212, 103, 65, 238, 36, 59, 126, 183,
            77, 210, 20, 154, 10, 177, 185, 36, 111, 179, 3, 130, 242, 126, 133, 61, 133, 133, 113,
            158, 14, 103, 203, 218, 13, 170, 143, 81, 103, 16, 100, 97, 93, 100, 90, 226, 122, 203,
            21, 191, 177, 68, 127, 69, 155,
        ];
        assert_eq!(sha512(&message, None), digest);
        assert_eq!(sha512(&message, Some(1)), digest);
    }

    #[test]
    fn test_sha512_iterated() {
        let message = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
        let digest: Sha512Digest = [
            59, 59, 112, 161, 93, 224, 176, 42, 40, 169, 175, 132, 163, 241, 179, 120, 220, 207, 0,
            170, 218, 103, 148, 139, 233, 16, 231, 222, 149, 188, 207, 62, 79, 243, 230, 180, 11,
            227, 73, 142, 98, 65, 85, 94, 195, 193, 135, 28, 111, 6, 221, 42, 150, 72, 174, 131,
            137, 249, 23, 197, 232, 4, 104, 109,
        ];
        assert_eq!(sha512(&message, Some(5)), digest);
    }
}
