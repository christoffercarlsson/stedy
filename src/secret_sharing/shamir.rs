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
        let mut coefficients: [F::Bytes; K] = from_fn(|_| F::Bytes::new());
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
                let bytes = F::Bytes::from_slice_checked(&share[begin..end])
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
        crate::{csprngs::ChaCha20Rng, elliptic_curves::Field25519},
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
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        assert_eq!(
            secret,
            [
                189, 98, 126, 118, 130, 133, 147, 107, 179, 195, 232, 245, 105, 149, 156, 11, 102,
                238, 246, 149, 42, 27, 28, 74, 169, 187, 175, 23, 175, 195, 58, 204
            ]
        );
        let mut output = [0u8; 108];
        let shares = shamir_split::<2, 3>(&mut rng, &secret, &mut output).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(
            shares[0],
            [
                0, 0, 0, 1, 119, 127, 157, 20, 165, 186, 73, 158, 204, 105, 118, 171, 189, 230,
                158, 29, 11, 58, 29, 191, 253, 26, 100, 130, 172, 26, 2, 181, 159, 90, 63, 40
            ]
        );
        assert_eq!(
            shares[1],
            [
                0, 0, 0, 2, 50, 88, 163, 178, 204, 251, 60, 154, 77, 140, 207, 73, 218, 115, 152,
                39, 188, 93, 59, 193, 159, 25, 236, 193, 163, 226, 238, 72, 207, 234, 48, 31
            ]
        );
        assert_eq!(
            shares[2],
            [
                0, 0, 0, 3, 248, 69, 64, 208, 235, 196, 230, 111, 50, 38, 81, 23, 14, 0, 154, 49,
                209, 137, 208, 235, 72, 24, 148, 9, 166, 67, 67, 234, 255, 115, 53, 251
            ]
        );
        let mut buffer = [0u8; 32];
        let result = shamir_combine([shares[2], shares[1]], &mut buffer).unwrap();
        assert_eq!(result, secret);
    }

    #[test]
    fn test_shamir_secret_sharing_high_threshold() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
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
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
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
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
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
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let mut output = [0u8; 12];
        let shares = shamir_split::<2, 3>(&mut rng, &[], &mut output).unwrap();
        assert_eq!(shares[0], [0, 0, 0, 1]);
        let mut buffer = [0u8; 1];
        let result = shamir_combine([shares[0], shares[2]], &mut buffer).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_shamir_secret_sharing_output_too_small() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let mut output = [0u8; 107];
        let result = shamir_split::<2, 3>(&mut rng, &[0u8; 32], &mut output);
        assert!(result.is_none());
    }

    #[test]
    fn test_shamir_secret_sharing_combine_zero_index() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
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
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
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
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        let mut output = [0u8; 204];
        let shares = Shamir::<Field25519>::split::<2, 3>(&mut rng, &secret, &mut output).unwrap();
        assert_eq!(
            shares[0],
            [
                0, 0, 0, 1, 135, 128, 97, 217, 169, 196, 109, 97, 51, 110, 135, 84, 62, 9, 159, 33,
                211, 194, 226, 192, 1, 29, 148, 18, 175, 92, 93, 186, 223, 92, 64, 100, 255, 185,
                144, 5, 108, 180, 103, 227, 33, 249, 180, 55, 133, 138, 84, 78, 248, 192, 49, 168,
                83, 96, 159, 150, 163, 210, 249, 205, 252, 103, 187, 90
            ]
        );
        assert_eq!(
            shares[1],
            [
                0, 0, 0, 2, 100, 158, 68, 60, 209, 3, 72, 87, 179, 24, 38, 179, 18, 125, 161, 55,
                64, 151, 206, 235, 216, 30, 12, 219, 180, 253, 10, 93, 16, 246, 69, 72, 69, 115,
                33, 11, 216, 104, 207, 198, 67, 242, 105, 111, 10, 21, 169, 156, 240, 129, 99, 80,
                167, 192, 62, 45, 71, 165, 243, 155, 249, 207, 118, 53
            ]
        );
        assert_eq!(
            shares[2],
            [
                0, 0, 0, 3, 65, 188, 39, 159, 248, 66, 34, 77, 51, 195, 196, 17, 231, 240, 163, 77,
                173, 107, 186, 22, 176, 32, 132, 163, 186, 158, 184, 255, 64, 143, 75, 44, 139, 44,
                178, 16, 68, 29, 55, 170, 101, 235, 30, 167, 143, 159, 253, 234, 232, 66, 149, 248,
                250, 32, 222, 195, 234, 119, 237, 105, 246, 55, 50, 16
            ]
        );
        let mut buffer = [0u8; 62];
        let result = Shamir::<Field25519>::combine([shares[2], shares[1]], &mut buffer).unwrap();
        assert_eq!(result.len(), 62);
        assert_eq!(result[..32], secret);
        assert_eq!(result[32..], [0u8; 30]);
    }
}
