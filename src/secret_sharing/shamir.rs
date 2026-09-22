use {
    crate::{
        secret_sharing::gf256::Gf256,
        traits::{ByteArray, ByteOrder, CryptoRng, FieldElement},
        utils::wipe,
    },
    core::{array::from_fn, marker::PhantomData},
};

pub struct Shamir<F: FieldElement> {
    _marker: PhantomData<F>,
}

impl<F: FieldElement> Shamir<F> {
    pub const CHUNK_SIZE: usize = F::CAPACITY / 8;
    pub const MAX_SHARES: usize = if F::CAPACITY < u32::BITS as usize {
        (1 << F::CAPACITY) - 1
    } else {
        u32::MAX as usize
    };

    pub fn split<'a, const K: usize, const N: usize>(
        rng: &mut impl CryptoRng,
        secret: &[u8],
        output: &'a mut [u8],
    ) -> Option<[&'a [u8]; N]> {
        const { assert!(N <= Self::MAX_SHARES, "Too many shares for the field") }
        const { assert!(K <= N, "Threshold exceeds the number of shares") }
        let columns = secret.len().div_ceil(Self::CHUNK_SIZE);
        let share_size = 4 + columns * Self::ELEMENT_SIZE;
        if N * share_size > output.len() {
            return None;
        }
        for (i, share) in output.chunks_mut(share_size).take(N).enumerate() {
            let x = (i + 1) as u32;
            share[..4].copy_from_slice(&x.to_be_bytes());
        }
        for share in output.chunks_mut(share_size).take(K).skip(1) {
            rng.fill(&mut share[4..]);
        }
        for i in 0..columns {
            let chunk = Self::encode_chunk(secret, i);
            Self::split_chunk::<K, N>(share_size, i, chunk, output);
        }
        let shares: [&'a [u8]; N] = from_fn(|i| {
            let begin = i * share_size;
            let end = begin + share_size;
            &output[begin..end]
        });
        Some(shares)
    }

    pub fn combine<'a, const K: usize>(
        shares: [&[u8]; K],
        secret: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        match Self::combine_secret(shares, secret) {
            Some(size) => Some(&secret[..size]),
            None => {
                wipe(secret);
                None
            }
        }
    }
}

pub fn shamir_split<'a, const K: usize, const N: usize>(
    rng: &mut impl CryptoRng,
    secret: &[u8],
    output: &'a mut [u8],
) -> Option<[&'a [u8]; N]> {
    Shamir::<Gf256>::split::<K, N>(rng, secret, output)
}

pub fn shamir_combine<'a, const K: usize>(
    shares: [&[u8]; K],
    secret: &'a mut [u8],
) -> Option<&'a [u8]> {
    Shamir::<Gf256>::combine::<K>(shares, secret)
}

impl<F: FieldElement> Shamir<F> {
    const ELEMENT_SIZE: usize = F::Bytes::SIZE;

    fn encode_chunk(secret: &[u8], index: usize) -> F::Bytes {
        let mut bytes = F::Bytes::new();
        let begin = index * Self::CHUNK_SIZE;
        let end = (begin + Self::CHUNK_SIZE).min(secret.len());
        let chunk = &secret[begin..end];
        bytes.as_mut()[..chunk.len()].copy_from_slice(chunk);
        bytes
    }

    fn split_chunk<const K: usize, const N: usize>(
        share_size: usize,
        index: usize,
        secret: F::Bytes,
        output: &mut [u8],
    ) {
        let coefficients = Self::calculate_coefficients::<K>(share_size, index, secret, output);
        let sub_shares: [F::Bytes; N] = from_fn(|i| {
            let x = (i + 1) as u32;
            Self::calculate_share(x, &coefficients)
        });
        for (i, sub_share) in sub_shares.iter().enumerate() {
            let begin = i * share_size + (4 + index * Self::ELEMENT_SIZE);
            let end = begin + Self::ELEMENT_SIZE;
            output[begin..end].copy_from_slice(sub_share.as_ref());
        }
    }

    fn calculate_coefficients<const K: usize>(
        share_size: usize,
        index: usize,
        secret: F::Bytes,
        output: &[u8],
    ) -> [F; K] {
        let mut coefficients = [F::Bytes::new(); K];
        coefficients[0] = Self::reverse_if_big_endian(secret);
        let offset = 4 + index * Self::ELEMENT_SIZE;
        for (i, coefficient) in coefficients.iter_mut().enumerate().skip(1) {
            let begin = i * share_size + offset;
            let end = begin + Self::ELEMENT_SIZE;
            coefficient.as_mut().copy_from_slice(&output[begin..end]);
        }
        coefficients.map(F::from)
    }

    fn calculate_share<const K: usize>(x: u32, coefficients: &[F; K]) -> F::Bytes {
        let x = F::from(x);
        let mut t = F::ZERO;
        for &coefficient in coefficients.iter().rev() {
            t = t * x + coefficient;
        }
        t.into()
    }

    fn calculate_columns<const K: usize>(shares: [&[u8]; K], secret: &[u8]) -> Option<usize> {
        let share_size = shares[0].len();
        if share_size < 4 {
            return None;
        }
        let payload_size = share_size - 4;
        if !payload_size.is_multiple_of(Self::ELEMENT_SIZE) {
            return None;
        }
        let valid = |share: &&[u8]| {
            share.len() == share_size
                && (1..=Self::MAX_SHARES).contains(&(Self::index(share) as usize))
        };
        if !shares.iter().all(valid) {
            return None;
        }
        let columns = payload_size / Self::ELEMENT_SIZE;
        if secret.len() >= columns * Self::CHUNK_SIZE {
            Some(columns)
        } else {
            None
        }
    }

    fn combine_column<const K: usize>(pairs: [(F, F); K]) -> F::Bytes {
        let mut secret = F::ZERO;
        for (j, &pair) in pairs.iter().enumerate().take(K) {
            let (xj, yj) = pair;
            let mut lambda = F::ONE;
            for (m, &pair) in pairs.iter().enumerate().take(K) {
                if m == j {
                    continue;
                }
                let (xm, _) = pair;
                lambda *= xm / (xm - xj);
            }
            secret += yj * lambda;
        }
        Self::reverse_if_big_endian(secret.into())
    }

    fn combine_secret<const K: usize>(shares: [&[u8]; K], secret: &mut [u8]) -> Option<usize> {
        let columns = Self::calculate_columns(shares, secret)?;
        for i in 0..columns {
            let begin = 4 + i * Self::ELEMENT_SIZE;
            let end = begin + Self::ELEMENT_SIZE;
            let pairs: [(F, F); K] = from_fn(|j| {
                let share = shares[j];
                let bytes = *F::Bytes::from_slice_checked(&share[begin..end])
                    .expect("Each secret column is one field element");
                let x = F::from(Self::index(share));
                let y = F::from(bytes);
                (x, y)
            });
            let src = Self::combine_column(pairs);
            let offset = i * Self::CHUNK_SIZE;
            secret[offset..offset + Self::CHUNK_SIZE]
                .copy_from_slice(&src.as_ref()[..Self::CHUNK_SIZE]);
        }
        Some(columns * Self::CHUNK_SIZE)
    }

    fn index(share: &[u8]) -> u32 {
        u32::from_be_bytes([share[0], share[1], share[2], share[3]])
    }

    fn reverse_if_big_endian(mut bytes: F::Bytes) -> F::Bytes {
        if F::BYTE_ORDER == ByteOrder::BigEndian {
            bytes.as_mut().reverse();
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{csprngs::Rng, elliptic_curves::Field25519},
    };

    #[test]
    fn test_shamir_chunk_size() {
        assert_eq!(Shamir::<Gf256>::CHUNK_SIZE, 1);
        assert_eq!(Shamir::<Field25519>::CHUNK_SIZE, 31);
    }

    #[test]
    fn test_shamir_max_shares() {
        assert_eq!(Shamir::<Gf256>::MAX_SHARES, 255);
        assert_eq!(Shamir::<Field25519>::MAX_SHARES, u32::MAX as usize);
    }

    #[test]
    fn test_shamir_secret_sharing() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        assert_eq!(
            secret,
            [
                253, 205, 139, 38, 230, 153, 90, 68, 159, 27, 68, 57, 5, 242, 232, 217, 162, 213,
                40, 127, 15, 170, 40, 184, 218, 178, 64, 246, 99, 149, 165, 24
            ]
        );
        let mut output = [0u8; 108];
        let shares = shamir_split::<2, 3>(&mut rng, &secret, &mut output).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(
            shares[0],
            [
                0, 0, 0, 1, 169, 13, 213, 212, 208, 10, 135, 108, 234, 110, 205, 88, 22, 152, 31,
                110, 202, 184, 140, 121, 2, 227, 50, 157, 7, 60, 149, 200, 239, 134, 7, 217
            ]
        );
        assert_eq!(
            shares[1],
            [
                0, 0, 0, 2, 85, 86, 55, 217, 138, 164, 251, 20, 117, 241, 77, 251, 35, 38, 29, 172,
                114, 15, 123, 115, 21, 56, 28, 242, 123, 181, 241, 138, 96, 179, 250, 129
            ]
        );
        assert_eq!(
            shares[2],
            [
                0, 0, 0, 3, 1, 150, 105, 43, 188, 55, 38, 60, 0, 132, 196, 154, 48, 76, 234, 27,
                26, 98, 223, 117, 24, 113, 6, 215, 166, 59, 36, 180, 236, 160, 88, 64
            ]
        );
        let mut buffer = [0u8; 32];
        let result = shamir_combine([shares[2], shares[1]], &mut buffer).unwrap();
        assert_eq!(result, secret);
    }

    #[test]
    fn test_shamir_secret_sharing_high_threshold() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        let mut output = [0u8; 540];
        let shares = shamir_split::<12, 15>(&mut rng, &secret, &mut output).unwrap();
        let mut buffer = [0u8; 32];
        let picked = [
            shares[14], shares[13], shares[12], shares[11], shares[10], shares[9], shares[8],
            shares[7], shares[6], shares[5], shares[4], shares[3],
        ];
        let result = shamir_combine(picked, &mut buffer).unwrap();
        assert_eq!(result, secret);
    }

    #[test]
    fn test_shamir_secret_sharing_long_arrays() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        let mut output = [0u8; 1024];
        let shares = shamir_split::<2, 3>(&mut rng, &secret, &mut output).unwrap();
        let mut buffer = [0u8; 1024];
        let result = shamir_combine([shares[2], shares[1]], &mut buffer).unwrap();
        assert_eq!(result, secret);
    }

    #[test]
    fn test_shamir_secret_sharing_max_shares() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        let mut output = [0u8; 9180];
        let shares = shamir_split::<2, 255>(&mut rng, &secret, &mut output).unwrap();
        assert_eq!(shares[254][..4], [0, 0, 0, 255]);
        let mut buffer = [0u8; 32];
        let result = shamir_combine([shares[254], shares[0]], &mut buffer).unwrap();
        assert_eq!(result, secret);
    }

    #[test]
    fn test_shamir_secret_sharing_empty_secret() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut output = [0u8; 12];
        let shares = shamir_split::<2, 3>(&mut rng, &[], &mut output).unwrap();
        assert_eq!(shares[0], [0, 0, 0, 1]);
        let mut buffer = [0u8; 1];
        let result = shamir_combine([shares[0], shares[2]], &mut buffer).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_shamir_secret_sharing_output_too_small() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut output = [0u8; 107];
        let result = shamir_split::<2, 3>(&mut rng, &[0u8; 32], &mut output);
        assert!(result.is_none());
    }

    #[test]
    fn test_shamir_secret_sharing_combine_zero_index() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut output = [0u8; 21];
        let shares = shamir_split::<2, 3>(&mut rng, &[1, 2, 3], &mut output).unwrap();
        let mut share = [0u8; 7];
        share.copy_from_slice(shares[0]);
        share[3] = 0;
        let mut buffer = [0u8; 3];
        let result = shamir_combine([&share, shares[1]], &mut buffer);
        assert!(result.is_none());
    }

    #[test]
    fn test_shamir_secret_sharing_combine_index_above_maximum() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut output = [0u8; 21];
        let shares = shamir_split::<2, 3>(&mut rng, &[1, 2, 3], &mut output).unwrap();
        let mut share = [0u8; 7];
        share.copy_from_slice(shares[0]);
        share[2] = 1;
        let mut buffer = [0u8; 3];
        let result = shamir_combine([&share, shares[1]], &mut buffer);
        assert!(result.is_none());
    }

    #[test]
    fn test_shamir_field25519() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        let mut output = [0u8; 204];
        let shares = Shamir::<Field25519>::split::<2, 3>(&mut rng, &secret, &mut output).unwrap();
        assert_eq!(
            shares[0],
            [
                0, 0, 0, 1, 81, 142, 234, 24, 29, 45, 56, 109, 20, 145, 205, 154, 24, 92, 224, 145,
                11, 67, 205, 133, 28, 243, 66, 221, 183, 65, 22, 53, 240, 168, 71, 66, 100, 18,
                254, 50, 63, 26, 142, 145, 216, 22, 213, 220, 46, 154, 215, 91, 38, 121, 86, 133,
                36, 75, 124, 121, 25, 5, 80, 35, 169, 175, 29, 102
            ]
        );
        assert_eq!(
            shares[1],
            [
                0, 0, 0, 2, 184, 78, 73, 11, 84, 192, 21, 150, 137, 6, 87, 252, 43, 198, 215, 73,
                116, 176, 113, 140, 41, 60, 93, 2, 149, 208, 235, 115, 124, 188, 233, 3, 195, 36,
                252, 101, 126, 52, 28, 35, 177, 45, 170, 185, 93, 52, 175, 183, 76, 242, 172, 10,
                73, 150, 248, 242, 50, 10, 160, 70, 82, 95, 59, 76
            ]
        );
        assert_eq!(
            shares[2],
            [
                0, 0, 0, 3, 12, 15, 168, 253, 138, 83, 243, 190, 254, 123, 224, 93, 63, 48, 207, 1,
                221, 29, 22, 147, 54, 133, 119, 39, 114, 95, 193, 178, 8, 208, 139, 69, 34, 55,
                250, 152, 189, 78, 170, 180, 137, 68, 127, 150, 140, 206, 134, 19, 115, 107, 3,
                144, 109, 225, 116, 108, 76, 15, 240, 105, 251, 14, 89, 50
            ]
        );
        let mut buffer = [0u8; 62];
        let result = Shamir::<Field25519>::combine([shares[2], shares[1]], &mut buffer).unwrap();
        assert_eq!(result.len(), 62);
        assert_eq!(result[..32], secret);
        assert_eq!(result[32..], [0u8; 30]);
    }
}
