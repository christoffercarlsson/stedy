use {
    crate::{
        elliptic_curves::Field25519,
        traits::{ByteArray, ByteOrder, CryptoRng, FieldElement},
        utils::{pad_to_capacity, unpad, wipe},
    },
    core::{array::from_fn, marker::PhantomData},
};

pub struct Shamir<F: FieldElement> {
    _marker: PhantomData<F>,
}

impl<F: FieldElement> Shamir<F> {
    pub fn split<'a, const K: usize, const N: usize>(
        rng: &mut impl CryptoRng,
        secret: &[u8],
        output: &'a mut [u8],
    ) -> Option<[&'a [u8]; N]> {
        let share_size = Self::calculate_share_size(secret);
        let total_size = N * share_size;
        if total_size > output.len() {
            return None;
        }
        for (i, chunk) in secret.chunks(Self::CHUNK_SIZE).enumerate() {
            let mut padded = F::Bytes::new();
            pad_to_capacity(chunk, padded.as_mut());
            Self::split_chunk::<K, N>(rng, share_size, i, padded, output);
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
        let size = Self::combine_secret(shares, secret).unwrap_or_else(|| {
            wipe(secret);
            0
        });
        if size == 0 {
            None
        } else {
            Some(&secret[..size])
        }
    }
}

pub fn shamir_split<'a, const K: usize, const N: usize>(
    rng: &mut impl CryptoRng,
    secret: &[u8],
    output: &'a mut [u8],
) -> Option<[&'a [u8]; N]> {
    Shamir::<Field25519>::split::<K, N>(rng, secret, output)
}

pub fn shamir_combine<'a, const K: usize>(
    shares: [&[u8]; K],
    secret: &'a mut [u8],
) -> Option<&'a [u8]> {
    Shamir::<Field25519>::combine::<K>(shares, secret)
}

impl<F: FieldElement> Shamir<F> {
    const ELEMENT_SIZE: usize = F::Bytes::SIZE;
    const CHUNK_SIZE: usize = (F::BITS - 1) / 8 - 1;

    fn calculate_share_size(secret: &[u8]) -> usize {
        let secret_size = secret.len();
        let mut chunk_count = secret_size / Self::CHUNK_SIZE;
        let remainder = secret_size % Self::CHUNK_SIZE;
        if remainder > 0 {
            chunk_count += 1;
        }
        4 + chunk_count * Self::ELEMENT_SIZE
    }

    fn split_chunk<const K: usize, const N: usize>(
        rng: &mut impl CryptoRng,
        share_size: usize,
        index: usize,
        secret: F::Bytes,
        output: &mut [u8],
    ) {
        let coefficients = Self::calculate_coefficients::<K>(rng, secret);
        let sub_shares: [F::Bytes; N] = from_fn(|i| {
            let x = (i + 1) as u32;
            Self::calculate_share(x, &coefficients)
        });
        for (i, sub_share) in sub_shares.iter().enumerate() {
            let begin = i * share_size + (4 + index * Self::ELEMENT_SIZE);
            let end = begin + Self::ELEMENT_SIZE;
            output[begin..end].copy_from_slice(sub_share.as_ref());
            if index == 0 {
                let x = (i + 1) as u32;
                output[(begin - 4)..begin].copy_from_slice(&x.to_be_bytes());
            }
        }
    }

    fn calculate_coefficients<const K: usize>(
        rng: &mut impl CryptoRng,
        secret: F::Bytes,
    ) -> [F; K] {
        let mut coefficients = [F::Bytes::new(); K];
        coefficients[0] = Self::reverse_if_big_endian(secret);
        for coefficient in coefficients.iter_mut().take(K).skip(1) {
            rng.fill(coefficient.as_mut());
        }
        coefficients.map(|bytes| F::from(bytes))
    }

    fn calculate_share<const K: usize>(x: u32, coefficients: &[F; K]) -> F::Bytes {
        let mut t = coefficients[0];
        for (i, &coefficient) in coefficients.iter().enumerate().take(K).skip(1) {
            t += coefficient * F::from(x.pow(i as u32));
        }
        t.into()
    }

    fn calculate_columns<const K: usize>(shares: [&[u8]; K], secret: &[u8]) -> Option<usize> {
        let share_size = shares[0].len();
        if share_size < 4 + Self::ELEMENT_SIZE {
            return None;
        }
        let payload_size = share_size - 4;
        if !payload_size.is_multiple_of(Self::ELEMENT_SIZE) {
            return None;
        }
        if !shares[1..].iter().all(|share| share.len() == share_size) {
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
        let mut offset: usize = 0;
        for i in 0..columns {
            let begin = 4 + i * Self::ELEMENT_SIZE;
            let end = begin + Self::ELEMENT_SIZE;
            let pairs: [(F, F); K] = from_fn(|j| {
                let share = shares[j];
                let index = u32::from_be_bytes([share[0], share[1], share[2], share[3]]);
                let bytes = *F::Bytes::from_slice_checked(&share[begin..end])
                    .expect("Each secret column is one field element");
                let x = F::from(index);
                let y = F::from(bytes);
                (x, y)
            });
            let src = Self::combine_column(pairs);
            let unpadded = unpad(src.as_ref()).unwrap_or(&src.as_ref()[..Self::CHUNK_SIZE]);
            let size = unpadded.len();
            secret[offset..offset + size].copy_from_slice(unpadded);
            offset += size;
        }
        Some(offset)
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
    use {super::*, crate::csprngs::Rng};

    #[test]
    fn test_shamir_secret_sharing() {
        let mut rng = Rng::from(&[0u8; 128]);
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        assert_eq!(
            secret,
            [
                89, 151, 243, 239, 17, 196, 251, 133, 30, 56, 89, 220, 74, 144, 209, 105, 150, 125,
                139, 44, 132, 127, 191, 13, 64, 39, 240, 246, 10, 240, 124, 104
            ]
        );
        let mut output = [0u8; 204];
        let shares = shamir_split::<2, 3>(&mut rng, &secret, &mut output).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(
            shares[0],
            [
                0, 0, 0, 1, 197, 41, 107, 89, 22, 200, 209, 43, 49, 96, 244, 137, 214, 178, 206,
                73, 16, 184, 235, 95, 20, 12, 152, 103, 97, 217, 153, 143, 13, 242, 220, 0, 138,
                58, 236, 149, 175, 222, 110, 64, 71, 138, 111, 46, 228, 249, 36, 115, 207, 95, 167,
                198, 254, 54, 36, 42, 174, 255, 53, 160, 250, 74, 236, 10
            ]
        );
        assert_eq!(
            shares[1],
            [
                0, 0, 0, 2, 49, 188, 226, 194, 26, 204, 167, 209, 67, 136, 143, 55, 98, 213, 203,
                41, 138, 242, 75, 147, 164, 152, 112, 193, 130, 139, 67, 40, 16, 244, 56, 1, 152,
                12, 88, 43, 95, 189, 221, 128, 142, 20, 223, 92, 200, 243, 73, 230, 158, 191, 78,
                141, 253, 109, 72, 84, 92, 255, 107, 64, 245, 149, 216, 21
            ]
        );
        assert_eq!(
            shares[2],
            [
                0, 0, 0, 3, 157, 78, 90, 44, 31, 208, 125, 119, 86, 176, 42, 229, 237, 247, 200, 9,
                4, 45, 172, 198, 52, 37, 73, 27, 164, 61, 237, 192, 18, 246, 148, 1, 166, 222, 195,
                192, 14, 156, 76, 193, 213, 158, 78, 139, 172, 237, 110, 89, 110, 31, 246, 83, 252,
                164, 108, 126, 10, 255, 161, 224, 239, 224, 196, 32
            ]
        );
        let mut buffer = [0u8; 60];
        let result = shamir_combine([shares[2], shares[1]], &mut buffer).unwrap();
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
}
