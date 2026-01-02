use {
    crate::{
        curve25519::Curve25519,
        pad::{pad, unpad},
        traits::{Csprng, FieldElement},
        wipe::wipe,
    },
    core::{array::from_fn, marker::PhantomData},
};

pub struct Shamir<F: FieldElement<Bytes = [u8; 32]>> {
    _f: PhantomData<F>,
}

impl<F: FieldElement<Bytes = [u8; 32]>> Shamir<F> {
    pub fn split<'a, const N: usize, const K: usize>(
        rng: &mut impl Csprng,
        secret: &[u8],
        output: &'a mut [u8],
    ) -> Option<[&'a [u8]; N]> {
        let share_size = Self::calculate_share_size(secret);
        let total_size = N * share_size;
        if total_size > output.len() {
            return None;
        }
        for (i, chunk) in secret.chunks(30).enumerate() {
            let mut padded = [0u8; 32];
            pad(chunk, 32, &mut padded);
            Self::split_chunk::<N, K>(rng, share_size, i, padded, output);
        }
        let shares: [&'a [u8]; N] = from_fn(|i| {
            let begin = i * share_size;
            let end = begin + share_size;
            &output[begin..end]
        });
        Some(shares)
    }

    pub fn combine<const K: usize>(shares: [&[u8]; K], secret: &mut [u8]) -> Option<usize> {
        let secret_size = Self::combine_secret(shares, secret).unwrap_or_else(|| {
            wipe(secret);
            0
        });
        if secret_size == 0 {
            None
        } else {
            Some(secret_size)
        }
    }
}

pub fn sss_split<'a, const N: usize, const K: usize>(
    rng: &mut impl Csprng,
    secret: &[u8],
    output: &'a mut [u8],
) -> Option<[&'a [u8]; N]> {
    Shamir::<Curve25519>::split::<N, K>(rng, secret, output)
}

pub fn sss_combine<const K: usize>(shares: [&[u8]; K], secret: &mut [u8]) -> Option<usize> {
    Shamir::<Curve25519>::combine::<K>(shares, secret)
}

impl<F: FieldElement<Bytes = [u8; 32]>> Shamir<F> {
    fn calculate_share_size(secret: &[u8]) -> usize {
        let secret_size = secret.len();
        let mut chunk_count = secret_size / 30;
        let remainder = secret_size % 30;
        if remainder > 0 {
            chunk_count += 1;
        }
        4 + chunk_count * 32
    }

    fn split_chunk<const N: usize, const K: usize>(
        rng: &mut impl Csprng,
        share_size: usize,
        index: usize,
        secret: [u8; 32],
        output: &mut [u8],
    ) {
        let coefficients = Self::calculate_coefficients::<K>(rng, secret);
        let sub_shares: [[u8; 32]; N] = from_fn(|i| {
            let x = (i + 1) as u32;
            Self::calculate_share(x, &coefficients)
        });
        for (i, sub_share) in sub_shares.iter().enumerate() {
            let begin = i * share_size + (4 + index * 32);
            let end = begin + 32;
            output[begin..end].copy_from_slice(sub_share);
            if index == 0 {
                let x = (i + 1) as u32;
                output[(begin - 4)..begin].copy_from_slice(&x.to_be_bytes());
            }
        }
    }

    fn calculate_coefficients<const K: usize>(rng: &mut impl Csprng, secret: [u8; 32]) -> [F; K] {
        let mut c = [[0u8; 32]; K];
        c[0] = secret;
        for i in 1..K {
            rng.fill(&mut c[i]);
        }
        c.map(|bytes| F::from(bytes))
    }

    fn calculate_share<const K: usize>(x: u32, c: &[F; K]) -> [u8; 32] {
        let mut t = c[0];
        for i in 1..K {
            t += c[i] * F::from(x.pow(i as u32));
        }
        t.into()
    }

    fn calculate_columns<const K: usize>(shares: [&[u8]; K]) -> Option<usize> {
        let share_size = shares[0].len();
        if share_size < 36 {
            return None;
        }
        let payload_size = share_size - 4;
        if payload_size % 32 != 0 {
            return None;
        }
        if !shares[1..].iter().all(|share| share.len() == share_size) {
            return None;
        }
        Some(payload_size / 32)
    }

    fn combine_column<const K: usize>(pairs: [(F, F); K]) -> [u8; 32] {
        let mut secret = F::ZERO;
        for j in 0..K {
            let xj = pairs[j].0;
            let yj = pairs[j].1;
            let mut lambda = F::ONE;
            for m in 0..K {
                if m == j {
                    continue;
                }
                let xm = pairs[m].0;
                lambda *= xm / (xm - xj);
            }
            secret += yj * lambda;
        }
        secret.into()
    }

    fn combine_secret<const K: usize>(shares: [&[u8]; K], secret: &mut [u8]) -> Option<usize> {
        let columns = Self::calculate_columns(shares)?;
        let mut offset: usize = 0;
        for i in 0..columns {
            let begin = 4 + i * 32;
            let end = begin + 32;
            let pairs: [(F, F); K] = from_fn(|j| {
                let share = shares[j];
                let index = u32::from_be_bytes([share[0], share[1], share[2], share[3]]);
                let bytes: [u8; 32] = share[begin..end].try_into().unwrap();
                let x = F::from(index);
                let y = F::from(bytes);
                (x, y)
            });
            let src = Self::combine_column(pairs);
            let size = unpad(&src, 32)?;
            let dest = secret.get_mut(offset..(offset + size))?;
            dest.copy_from_slice(&src[..size]);
            offset += size;
        }
        Some(offset)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::rng::Rng};

    #[test]
    fn test_sss() {
        let mut rng = Rng::from([0u8; 32]);
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        let mut output = [0u8; 204];
        let shares = sss_split::<3, 2>(&mut rng, &secret, &mut output).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].len(), 68);
        assert_eq!(shares[1].len(), 68);
        assert_eq!(shares[2].len(), 68);
        assert_eq!(shares[0][..4], [0, 0, 0, 1]);
        assert_eq!(shares[1][..4], [0, 0, 0, 2]);
        assert_eq!(shares[2][..4], [0, 0, 0, 3]);
        let mut result = [0u8; 32];
        let size = sss_combine([&shares[2], &shares[1]], &mut result).unwrap();
        assert_eq!(size, 32);
        assert_eq!(result[..size], secret);
    }

    #[test]
    fn test_sss_long_arrays() {
        let mut rng = Rng::from([0u8; 32]);
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        let mut output = [0u8; 1024];
        let shares = sss_split::<3, 2>(&mut rng, &secret, &mut output).unwrap();
        let mut result = [0u8; 1024];
        let size = sss_combine([&shares[2], &shares[1]], &mut result).unwrap();
        assert_eq!(result[..size], secret);
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn test_sss_getrandom() {
        let mut rng = Rng::seed().unwrap();
        let mut secret = [0u8; 42];
        rng.fill(&mut secret);
        let mut output = [0u8; 204];
        let shares = sss_split::<3, 2>(&mut rng, &secret, &mut output).unwrap();
        let mut result = [0u8; 42];
        sss_combine([&shares[0], &shares[1]], &mut result);
        assert_eq!(result, secret);
    }
}
