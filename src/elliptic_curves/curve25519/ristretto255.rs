use {
    super::{
        Field25519, Field25519With, Scalar25519,
        field::{abs, is_negative, sqrt_ratio_m1},
    },
    crate::{
        Error,
        elliptic_curves::Edwards,
        traits::{
            ByteArray, CryptoRng, EdwardsParams, EdwardsScalar, FieldArithmetic, FieldElement,
            Hasher,
        },
        utils::{Choice, Secret, SecretBytes, declassify, is_zero, xor},
    },
    core::marker::PhantomData,
};

pub struct Ristretto255;

impl Ristretto255 {
    pub fn is_valid(element: &[u8; 32]) -> bool {
        Ristretto::<Field25519>::is_valid(element)
    }

    pub fn from_uniform_bytes(bytes: &[u8; 64]) -> [u8; 32] {
        Ristretto::<Field25519>::from_uniform_bytes(bytes)
    }

    pub fn from_string<H>(context: &[u8], message: &[u8]) -> Result<[u8; 32], Error>
    where
        H: Hasher,
    {
        Ristretto::<Field25519>::from_string::<H>(context, message)
    }

    pub fn generate_element(rng: &mut impl CryptoRng) -> Result<[u8; 32], Error> {
        Ristretto::<Field25519>::generate_element(rng)
    }

    pub fn add(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], Error> {
        Ristretto::<Field25519>::add(a, b)
    }

    pub fn sub(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], Error> {
        Ristretto::<Field25519>::sub(a, b)
    }

    pub fn scalar_mult(scalar: &[u8; 32], element: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        let mut product = SecretBytes::new();
        Ristretto::<Field25519>::scalar_mult(scalar, element, product.get_mut())?;
        Ok(product)
    }

    pub fn scalar_mult_base(scalar: &[u8; 32]) -> Result<[u8; 32], Error> {
        Ristretto::<Field25519>::scalar_mult_base(scalar)
    }

    pub fn generate_scalar(rng: &mut impl CryptoRng) -> Result<SecretBytes<32>, Error> {
        let mut scalar = SecretBytes::new();
        Ristretto::<Field25519>::generate_scalar(rng, scalar.get_mut())?;
        Ok(scalar)
    }

    pub fn scalar_reduce(bytes: &[u8; 64]) -> SecretBytes<32> {
        let mut scalar = SecretBytes::new();
        Ristretto::<Field25519>::scalar_reduce(bytes, scalar.get_mut());
        scalar
    }

    pub fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        let mut sum = SecretBytes::new();
        Ristretto::<Field25519>::scalar_add(a, b, sum.get_mut())?;
        Ok(sum)
    }

    pub fn scalar_sub(a: &[u8; 32], b: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        let mut difference = SecretBytes::new();
        Ristretto::<Field25519>::scalar_sub(a, b, difference.get_mut())?;
        Ok(difference)
    }

    pub fn scalar_mul(a: &[u8; 32], b: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        let mut product = SecretBytes::new();
        Ristretto::<Field25519>::scalar_mul(a, b, product.get_mut())?;
        Ok(product)
    }

    pub fn scalar_negate(scalar: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        let mut negation = SecretBytes::new();
        Ristretto::<Field25519>::scalar_negate(scalar, negation.get_mut())?;
        Ok(negation)
    }

    pub fn scalar_complement(scalar: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        let mut complement = SecretBytes::new();
        Ristretto::<Field25519>::scalar_complement(scalar, complement.get_mut())?;
        Ok(complement)
    }

    pub fn scalar_invert(scalar: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        let mut inverse = SecretBytes::new();
        Ristretto::<Field25519>::scalar_invert(scalar, inverse.get_mut())?;
        Ok(inverse)
    }
}

pub struct Ristretto255With<A>(PhantomData<A>);

impl<A> Ristretto255With<A>
where
    A: FieldArithmetic<Bytes = [u8; 32]>,
{
    pub fn is_valid(element: &[u8; 32]) -> bool {
        Ristretto::<Field25519With<A>>::is_valid(element)
    }

    pub fn from_uniform_bytes(bytes: &[u8; 64]) -> [u8; 32] {
        Ristretto::<Field25519With<A>>::from_uniform_bytes(bytes)
    }

    pub fn from_string<H>(context: &[u8], message: &[u8]) -> Result<[u8; 32], Error>
    where
        H: Hasher,
    {
        Ristretto::<Field25519With<A>>::from_string::<H>(context, message)
    }

    pub fn generate_element(rng: &mut impl CryptoRng) -> Result<[u8; 32], Error> {
        Ristretto::<Field25519With<A>>::generate_element(rng)
    }

    pub fn add(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], Error> {
        Ristretto::<Field25519With<A>>::add(a, b)
    }

    pub fn sub(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], Error> {
        Ristretto::<Field25519With<A>>::sub(a, b)
    }

    pub fn scalar_mult(scalar: &[u8; 32], element: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        let mut product = SecretBytes::new();
        Ristretto::<Field25519With<A>>::scalar_mult(scalar, element, product.get_mut())?;
        Ok(product)
    }

    pub fn scalar_mult_base(scalar: &[u8; 32]) -> Result<[u8; 32], Error> {
        Ristretto::<Field25519With<A>>::scalar_mult_base(scalar)
    }

    pub fn generate_scalar(rng: &mut impl CryptoRng) -> Result<SecretBytes<32>, Error> {
        Ristretto255::generate_scalar(rng)
    }

    pub fn scalar_reduce(bytes: &[u8; 64]) -> SecretBytes<32> {
        Ristretto255::scalar_reduce(bytes)
    }

    pub fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        Ristretto255::scalar_add(a, b)
    }

    pub fn scalar_sub(a: &[u8; 32], b: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        Ristretto255::scalar_sub(a, b)
    }

    pub fn scalar_mul(a: &[u8; 32], b: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        Ristretto255::scalar_mul(a, b)
    }

    pub fn scalar_negate(scalar: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        Ristretto255::scalar_negate(scalar)
    }

    pub fn scalar_complement(scalar: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        Ristretto255::scalar_complement(scalar)
    }

    pub fn scalar_invert(scalar: &[u8; 32]) -> Result<SecretBytes<32>, Error> {
        Ristretto255::scalar_invert(scalar)
    }
}

const SQRT_M1: [u8; 32] = [
    176, 160, 14, 74, 39, 27, 238, 196, 120, 228, 47, 173, 6, 24, 67, 47, 167, 215, 251, 61, 153,
    0, 77, 43, 11, 223, 193, 79, 128, 36, 131, 43,
];

const SQRT_AD_MINUS_ONE: [u8; 32] = [
    27, 46, 123, 73, 160, 246, 151, 126, 189, 84, 120, 27, 12, 142, 157, 175, 253, 209, 245, 49,
    201, 252, 60, 15, 172, 72, 131, 43, 191, 49, 105, 55,
];

const INVSQRT_A_MINUS_D: [u8; 32] = [
    234, 64, 93, 128, 170, 253, 200, 153, 190, 114, 65, 90, 23, 22, 47, 157, 64, 216, 1, 254, 145,
    123, 194, 22, 162, 252, 175, 207, 5, 137, 108, 120,
];

const ONE_MINUS_D_SQ: [u8; 32] = [
    118, 193, 95, 148, 193, 9, 124, 226, 15, 53, 94, 205, 56, 161, 129, 44, 228, 223, 112, 190,
    221, 171, 148, 153, 215, 224, 179, 178, 168, 114, 144, 2,
];

const D_MINUS_ONE_SQ: [u8; 32] = [
    32, 77, 237, 68, 170, 90, 173, 49, 153, 25, 30, 176, 44, 74, 158, 210, 235, 78, 155, 82, 47,
    211, 220, 76, 65, 34, 108, 246, 122, 179, 104, 89,
];

const SCALAR_ONE: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

struct Ristretto<F>(PhantomData<F>);

impl<F> Ristretto<F>
where
    F: FieldElement<Bytes = [u8; 32]> + EdwardsParams<F>,
{
    fn is_valid(element: &[u8; 32]) -> bool {
        let (_, valid) = Self::decode(element);
        valid.to_bool()
    }

    fn from_uniform_bytes(bytes: &[u8; 64]) -> [u8; 32] {
        let (halves, _) = bytes.as_chunks::<32>();
        Self::encode(&(Self::map(&halves[0]) + Self::map(&halves[1])))
    }

    fn from_string<H>(context: &[u8], message: &[u8]) -> Result<[u8; 32], Error>
    where
        H: Hasher,
    {
        const { assert!(H::OUTPUT_SIZE >= 32, "the hash output is at least 32 bytes") }
        if context.is_empty() {
            return Err(Error::Misuse);
        }
        let mut bytes = Secret::from([0u8; 64]);
        Self::expand_message_xmd::<H>(context, message, bytes.get_mut());
        Ok(Self::from_uniform_bytes(bytes.get()))
    }

    fn generate_element(rng: &mut impl CryptoRng) -> Result<[u8; 32], Error> {
        let mut bytes = Secret::from([0u8; 64]);
        rng.fill(bytes.get_mut())?;
        Ok(Self::from_uniform_bytes(bytes.get()))
    }

    fn add(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], Error> {
        Ok(Self::encode(&(Self::element(a)? + Self::element(b)?)))
    }

    fn sub(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], Error> {
        Ok(Self::encode(&(Self::element(a)? + -Self::element(b)?)))
    }

    fn scalar_mult(
        scalar: &[u8; 32],
        element: &[u8; 32],
        product: &mut [u8; 32],
    ) -> Result<(), Error> {
        let point = Self::element(element)?;
        let scalar = Self::scalar(scalar)?;
        let result = Secret::from(point * scalar);
        *product = Self::encode(result.get());
        if declassify(is_zero(product)).to_bool() {
            return Err(Error::InvalidKey);
        }
        Ok(())
    }

    fn scalar_mult_base(scalar: &[u8; 32]) -> Result<[u8; 32], Error> {
        let scalar = Self::scalar(scalar)?;
        let product = Self::encode(&Edwards::<F, Scalar25519>::mul_base(&scalar));
        if declassify(is_zero(&product)).to_bool() {
            return Err(Error::InvalidKey);
        }
        Ok(product)
    }

    fn generate_scalar(rng: &mut impl CryptoRng, scalar: &mut [u8; 32]) -> Result<(), Error> {
        loop {
            let mut bytes = Secret::from([0u8; 64]);
            rng.fill(bytes.get_mut())?;
            Self::scalar_reduce(bytes.get(), scalar);
            if !declassify(is_zero(scalar)).to_bool() {
                return Ok(());
            }
        }
    }

    fn scalar_reduce(bytes: &[u8; 64], scalar: &mut [u8; 32]) {
        *scalar = Scalar25519::from(bytes).into();
    }

    fn scalar_add(a: &[u8; 32], b: &[u8; 32], sum: &mut [u8; 32]) -> Result<(), Error> {
        *sum = (Self::scalar(a)? + Self::scalar(b)?).into();
        Ok(())
    }

    fn scalar_sub(a: &[u8; 32], b: &[u8; 32], difference: &mut [u8; 32]) -> Result<(), Error> {
        *difference = (Self::scalar(a)? + -Self::scalar(b)?).into();
        Ok(())
    }

    fn scalar_mul(a: &[u8; 32], b: &[u8; 32], product: &mut [u8; 32]) -> Result<(), Error> {
        *product = (Self::scalar(a)? * Self::scalar(b)?).into();
        Ok(())
    }

    fn scalar_negate(scalar: &[u8; 32], negation: &mut [u8; 32]) -> Result<(), Error> {
        *negation = (-Self::scalar(scalar)?).into();
        Ok(())
    }

    fn scalar_complement(scalar: &[u8; 32], complement: &mut [u8; 32]) -> Result<(), Error> {
        *complement = (Scalar25519::from(&SCALAR_ONE) + -Self::scalar(scalar)?).into();
        Ok(())
    }

    fn scalar_invert(scalar: &[u8; 32], inverse: &mut [u8; 32]) -> Result<(), Error> {
        let value = Self::scalar(scalar)?;
        if declassify(is_zero(scalar)).to_bool() {
            return Err(Error::InvalidKey);
        }
        *inverse = value.invert().into();
        Ok(())
    }

    fn element(bytes: &[u8; 32]) -> Result<Edwards<F, Scalar25519>, Error> {
        let (point, valid) = Self::decode(bytes);
        if valid.to_bool() {
            Ok(point)
        } else {
            Err(Error::Encoding)
        }
    }

    fn scalar(bytes: &[u8; 32]) -> Result<Scalar25519, Error> {
        if declassify(Scalar25519::is_canonical(bytes)).to_bool() {
            Ok(Scalar25519::from(bytes))
        } else {
            Err(Error::Encoding)
        }
    }

    // Section 4.3.1
    fn decode(bytes: &[u8; 32]) -> (Edwards<F, Scalar25519>, Choice) {
        let s = F::from(*bytes);
        let encoded: [u8; 32] = s.into();
        let canonical = Choice::eq_slice(&encoded, bytes);
        let ss = s.square();
        let u1 = F::ONE - ss;
        let u2 = F::ONE + ss;
        let u2_sqr = u2.square();
        let v = (F::D * u1.square()).neg() - u2_sqr;
        let (was_square, invsqrt) = sqrt_ratio_m1(F::ONE, v * u2_sqr, F::from(SQRT_M1));
        let den_x = invsqrt * u2;
        let den_y = invsqrt * den_x * v;
        let x = abs((s + s) * den_x);
        let y = u1 * den_y;
        let t = x * y;
        let valid = canonical & !is_negative(s) & was_square & !is_negative(t) & !y.ct_eq(&F::ZERO);
        (Edwards::new(x, y, t, F::ONE), valid)
    }

    // Section 4.3.2
    fn encode(point: &Edwards<F, Scalar25519>) -> [u8; 32] {
        let (x0, y0, t0, z0) = point.coordinates();
        let sqrt_m1 = F::from(SQRT_M1);
        let u1 = (z0 + y0) * (z0 - y0);
        let u2 = x0 * y0;
        let (_, invsqrt) = sqrt_ratio_m1(F::ONE, u1 * u2.square(), sqrt_m1);
        let den1 = invsqrt * u1;
        let den2 = invsqrt * u2;
        let z_inv = den1 * den2 * t0;
        let ix0 = x0 * sqrt_m1;
        let iy0 = y0 * sqrt_m1;
        let enchanted_denominator = den1 * F::from(INVSQRT_A_MINUS_D);
        let rotate = is_negative(t0 * z_inv);
        let x = F::select(&x0, &iy0, rotate);
        let y = F::select(&y0, &ix0, rotate);
        let den_inv = F::select(&den2, &enchanted_denominator, rotate);
        let y = F::select(&y, &y.neg(), is_negative(x * z_inv));
        abs(den_inv * (z0 - y)).into()
    }

    // Section 4.3.4
    fn map(bytes: &[u8; 32]) -> Edwards<F, Scalar25519> {
        let mut bytes = *bytes;
        bytes[31] &= 127;
        let t = F::from(bytes);
        let r = F::from(SQRT_M1) * t.square();
        let u = (r + F::ONE) * F::from(ONE_MINUS_D_SQ);
        let v = (F::ONE.neg() - r * F::D) * (r + F::D);
        let (was_square, s) = sqrt_ratio_m1(u, v, F::from(SQRT_M1));
        let s_prime = abs(s * t).neg();
        let s = F::select(&s_prime, &s, was_square);
        let c = F::select(&r, &F::ONE.neg(), was_square);
        let n = c * (r - F::ONE) * F::from(D_MINUS_ONE_SQ) - v;
        let w0 = (s + s) * v;
        let w1 = n * F::from(SQRT_AD_MINUS_ONE);
        let ss = s.square();
        let w2 = F::ONE - ss;
        let w3 = F::ONE + ss;
        Edwards::new(w0 * w3, w2 * w1, w0 * w2, w1 * w3)
    }

    // RFC 9380, Section 5.3.1
    fn expand_message_xmd<H>(context: &[u8], message: &[u8], output: &mut [u8])
    where
        H: Hasher,
    {
        let oversize;
        let context = if context.len() > 255 {
            let mut hasher = H::new();
            hasher.update(b"H2C-OVERSIZE-DST-");
            hasher.update(context);
            oversize = hasher.finalize();
            oversize.as_ref()
        } else {
            context
        };
        let context_size = [context.len() as u8];
        let mut hasher = H::new();
        hasher.update(H::Block::new().as_ref());
        hasher.update(message);
        hasher.update(&(output.len() as u16).to_be_bytes());
        hasher.update(&[0]);
        hasher.update(context);
        hasher.update(&context_size);
        let b0 = Secret::from(hasher.finalize());
        let mut bi = Secret::from(H::Output::new());
        for (i, chunk) in (1u8..).zip(output.chunks_mut(H::OUTPUT_SIZE)) {
            let mut input = Secret::from(b0.get().clone());
            xor(input.get_mut().as_mut(), bi.get().as_ref());
            let mut hasher = H::new();
            hasher.update(input.get().as_ref());
            hasher.update(&[i]);
            hasher.update(context);
            hasher.update(&context_size);
            bi = Secret::from(hasher.finalize());
            chunk.copy_from_slice(&bi.get().as_ref()[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            csprngs::ChaCha20Rng,
            hashes::{Sha256, Sha512},
        },
        hex_literal::hex,
    };

    // https://www.rfc-editor.org/rfc/rfc9496#appendix-A.1
    const MULTIPLES: [[u8; 32]; 16] = [
        hex!("0000000000000000000000000000000000000000000000000000000000000000"),
        hex!("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"),
        hex!("6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"),
        hex!("94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259"),
        hex!("da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57"),
        hex!("e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e"),
        hex!("f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403"),
        hex!("44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d"),
        hex!("903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c"),
        hex!("02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031"),
        hex!("20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f"),
        hex!("bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42"),
        hex!("e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460"),
        hex!("aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f"),
        hex!("46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e"),
        hex!("e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e"),
    ];

    // https://www.rfc-editor.org/rfc/rfc9496#section-4.4
    const ORDER: [u8; 32] =
        hex!("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");

    fn scalar(value: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = value;
        bytes
    }

    #[test]
    fn test_ristretto255_multiples_of_generator() {
        let mut sum = MULTIPLES[0];
        assert!(Ristretto255::is_valid(&MULTIPLES[0]));
        for (i, multiple) in (0u8..).zip(MULTIPLES.iter()).skip(1) {
            assert!(Ristretto255::is_valid(multiple));
            sum = Ristretto255::add(&sum, &MULTIPLES[1]).unwrap();
            assert_eq!(sum, *multiple);
            assert_eq!(
                Ristretto255::scalar_mult_base(&scalar(i)).unwrap(),
                *multiple
            );
            assert_eq!(
                Ristretto255::scalar_mult(&scalar(i), &MULTIPLES[1]).unwrap(),
                *multiple
            );
        }
        assert_eq!(
            Ristretto255::sub(&MULTIPLES[5], &MULTIPLES[3]).unwrap(),
            MULTIPLES[2]
        );
    }

    // https://www.rfc-editor.org/rfc/rfc9496#appendix-A.2
    #[test]
    fn test_ristretto255_invalid_encodings() {
        let encodings = [
            hex!("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex!("f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex!("0100000000000000000000000000000000000000000000000000000000000000"),
            hex!("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex!("ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20"),
            hex!("c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562"),
            hex!("c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78"),
            hex!("47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24"),
            hex!("f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72"),
            hex!("87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309"),
            hex!("26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371"),
            hex!("4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f"),
            hex!("de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b"),
            hex!("bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042"),
            hex!("2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08"),
            hex!("f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22"),
            hex!("8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731"),
            hex!("2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b"),
            hex!("3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e"),
            hex!("a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220"),
            hex!("d483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e"),
            hex!("8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32"),
            hex!("32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b"),
            hex!("227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165"),
            hex!("5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e"),
            hex!("445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b"),
            hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ];
        for encoding in encodings {
            assert!(!Ristretto255::is_valid(&encoding));
            assert_eq!(
                Ristretto255::add(&encoding, &MULTIPLES[1]),
                Err(Error::Encoding)
            );
            assert_eq!(
                Ristretto255::scalar_mult(&scalar(1), &encoding),
                Err(Error::Encoding)
            );
        }
    }

    // https://www.rfc-editor.org/rfc/rfc9496#appendix-A.3
    #[test]
    fn test_ristretto255_from_uniform_bytes() {
        let vectors = [
            (
                hex!(
                    "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6"
                ),
                hex!("3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46"),
            ),
            (
                hex!(
                    "f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b270102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38"
                ),
                hex!("f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b"),
            ),
            (
                hex!(
                    "8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c"
                ),
                hex!("006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826"),
            ),
            (
                hex!(
                    "ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf"
                ),
                hex!("f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a"),
            ),
            (
                hex!(
                    "165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec7675debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413"
                ),
                hex!("ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179"),
            ),
            (
                hex!(
                    "a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c"
                ),
                hex!("e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628"),
            ),
            (
                hex!(
                    "2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c74622c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982"
                ),
                hex!("80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065"),
            ),
            (
                hex!(
                    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1200000000000000000000000000000000000000000000000000000000000000"
                ),
                hex!("304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f"),
            ),
            (
                hex!(
                    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                ),
                hex!("304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f"),
            ),
            (
                hex!(
                    "0000000000000000000000000000000000000000000000000000000000000080ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
                ),
                hex!("304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f"),
            ),
            (
                hex!(
                    "00000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000080"
                ),
                hex!("304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f"),
            ),
        ];
        for (bytes, element) in vectors {
            assert_eq!(Ristretto255::from_uniform_bytes(&bytes), element);
        }
    }

    // https://www.rfc-editor.org/rfc/rfc9496#appendix-A.4
    #[test]
    fn test_ristretto255_sqrt_ratio_m1() {
        let vectors = [
            (
                hex!("0000000000000000000000000000000000000000000000000000000000000000"),
                hex!("0000000000000000000000000000000000000000000000000000000000000000"),
                true,
                hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            ),
            (
                hex!("0000000000000000000000000000000000000000000000000000000000000000"),
                hex!("0100000000000000000000000000000000000000000000000000000000000000"),
                true,
                hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            ),
            (
                hex!("0100000000000000000000000000000000000000000000000000000000000000"),
                hex!("0000000000000000000000000000000000000000000000000000000000000000"),
                false,
                hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            ),
            (
                hex!("0200000000000000000000000000000000000000000000000000000000000000"),
                hex!("0100000000000000000000000000000000000000000000000000000000000000"),
                false,
                hex!("3c5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54"),
            ),
            (
                hex!("0400000000000000000000000000000000000000000000000000000000000000"),
                hex!("0100000000000000000000000000000000000000000000000000000000000000"),
                true,
                hex!("0200000000000000000000000000000000000000000000000000000000000000"),
            ),
            (
                hex!("0100000000000000000000000000000000000000000000000000000000000000"),
                hex!("0400000000000000000000000000000000000000000000000000000000000000"),
                true,
                hex!("f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"),
            ),
        ];
        for (u, v, was_square, r) in vectors {
            let (square, root) = sqrt_ratio_m1(
                Field25519::from(u),
                Field25519::from(v),
                Field25519::from(SQRT_M1),
            );
            assert_eq!(square.to_bool(), was_square);
            assert_eq!(<[u8; 32]>::from(root), r);
        }
    }

    #[test]
    fn test_ristretto255_scalar_arithmetic() {
        let base = |s: &[u8; 32]| Ristretto255::scalar_mult_base(s).unwrap();
        let sum = Ristretto255::scalar_add(&scalar(2), &scalar(3)).unwrap();
        assert_eq!(base(&sum), MULTIPLES[5]);
        let difference = Ristretto255::scalar_sub(&scalar(7), &scalar(2)).unwrap();
        assert_eq!(base(&difference), MULTIPLES[5]);
        let product = Ristretto255::scalar_mul(&scalar(3), &scalar(5)).unwrap();
        assert_eq!(base(&product), MULTIPLES[15]);
        let negation = Ristretto255::scalar_negate(&scalar(1)).unwrap();
        assert_eq!(
            base(&negation),
            Ristretto255::sub(&MULTIPLES[0], &MULTIPLES[1]).unwrap()
        );
        let inverse = Ristretto255::scalar_invert(&scalar(2)).unwrap();
        let product = Ristretto255::scalar_mul(&inverse, &scalar(4)).unwrap();
        assert_eq!(base(&product), MULTIPLES[2]);
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&ORDER);
        wide[0] += 5;
        assert_eq!(base(&Ristretto255::scalar_reduce(&wide)), MULTIPLES[5]);
    }

    #[test]
    fn test_ristretto255_errors() {
        assert_eq!(
            Ristretto255::scalar_mult_base(&scalar(0)),
            Err(Error::InvalidKey)
        );
        assert_eq!(
            Ristretto255::scalar_mult(&scalar(5), &MULTIPLES[0]),
            Err(Error::InvalidKey)
        );
        assert_eq!(
            Ristretto255::scalar_invert(&scalar(0)),
            Err(Error::InvalidKey)
        );
        assert_eq!(
            Ristretto255::scalar_add(&ORDER, &scalar(1)),
            Err(Error::Encoding)
        );
        assert_eq!(Ristretto255::scalar_mult_base(&ORDER), Err(Error::Encoding));
    }

    #[test]
    fn test_ristretto255_generate() {
        let mut rng = ChaCha20Rng::from(&[0u8; 96]);
        let element = Ristretto255::generate_element(&mut rng).unwrap();
        assert!(Ristretto255::is_valid(&element));
        let scalar = Ristretto255::generate_scalar(&mut rng).unwrap();
        let product = Ristretto255::scalar_mult(&scalar, &element).unwrap();
        let inverse = Ristretto255::scalar_invert(&scalar).unwrap();
        assert_eq!(
            Ristretto255::scalar_mult(&inverse, &product).unwrap(),
            element
        );
    }

    fn padded<const N: usize>(prefix: &[u8], fill: u8) -> [u8; N] {
        let mut bytes = [fill; N];
        bytes[..prefix.len()].copy_from_slice(prefix);
        bytes
    }

    // https://www.rfc-editor.org/rfc/rfc9380#appendix-K.1
    #[test]
    fn test_expand_message_xmd_sha256() {
        let context = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let q128 = padded::<133>(b"q128_", b'q');
        let a512 = padded::<517>(b"a512_", b'a');
        let vectors: [(&[u8], usize, &[u8]); 10] = [
            (
                b"",
                32,
                &hex!("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"),
            ),
            (
                b"abc",
                32,
                &hex!("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"),
            ),
            (
                b"abcdef0123456789",
                32,
                &hex!("eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1"),
            ),
            (
                &q128[..],
                32,
                &hex!("b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9"),
            ),
            (
                &a512[..],
                32,
                &hex!("4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c"),
            ),
            (
                b"",
                128,
                &hex!(
                    "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"
                ),
            ),
            (
                b"abc",
                128,
                &hex!(
                    "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"
                ),
            ),
            (
                b"abcdef0123456789",
                128,
                &hex!(
                    "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df"
                ),
            ),
            (
                &q128[..],
                128,
                &hex!(
                    "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a"
                ),
            ),
            (
                &a512[..],
                128,
                &hex!(
                    "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487"
                ),
            ),
        ];
        for (message, size, uniform_bytes) in vectors {
            let mut output = [0u8; 128];
            Ristretto::<Field25519>::expand_message_xmd::<Sha256>(
                context,
                message,
                &mut output[..size],
            );
            assert_eq!(&output[..size], uniform_bytes);
        }
    }

    // https://www.rfc-editor.org/rfc/rfc9380#appendix-K.2
    #[test]
    fn test_expand_message_xmd_sha256_long_dst() {
        let context = b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
        let q128 = padded::<133>(b"q128_", b'q');
        let a512 = padded::<517>(b"a512_", b'a');
        let vectors: [(&[u8], usize, &[u8]); 10] = [
            (
                b"",
                32,
                &hex!("e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3"),
            ),
            (
                b"abc",
                32,
                &hex!("52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12"),
            ),
            (
                b"abcdef0123456789",
                32,
                &hex!("35387dcf22618f3728e6c686490f8b431f76550b0b2c61cbc1ce7001536f4521"),
            ),
            (
                &q128[..],
                32,
                &hex!("01b637612bb18e840028be900a833a74414140dde0c4754c198532c3a0ba42bc"),
            ),
            (
                &a512[..],
                32,
                &hex!("20cce7033cabc5460743180be6fa8aac5a103f56d481cf369a8accc0c374431b"),
            ),
            (
                b"",
                128,
                &hex!(
                    "14604d85432c68b757e485c8894db3117992fc57e0e136f71ad987f789a0abc287c47876978e2388a02af86b1e8d1342e5ce4f7aaa07a87321e691f6fba7e0072eecc1218aebb89fb14a0662322d5edbd873f0eb35260145cd4e64f748c5dfe60567e126604bcab1a3ee2dc0778102ae8a5cfd1429ebc0fa6bf1a53c36f55dfc"
                ),
            ),
            (
                b"abc",
                128,
                &hex!(
                    "1a30a5e36fbdb87077552b9d18b9f0aee16e80181d5b951d0471d55b66684914aef87dbb3626eaabf5ded8cd0686567e503853e5c84c259ba0efc37f71c839da2129fe81afdaec7fbdc0ccd4c794727a17c0d20ff0ea55e1389d6982d1241cb8d165762dbc39fb0cee4474d2cbbd468a835ae5b2f20e4f959f56ab24cd6fe267"
                ),
            ),
            (
                b"abcdef0123456789",
                128,
                &hex!(
                    "d2ecef3635d2397f34a9f86438d772db19ffe9924e28a1caf6f1c8f15603d4028f40891044e5c7e39ebb9b31339979ff33a4249206f67d4a1e7c765410bcd249ad78d407e303675918f20f26ce6d7027ed3774512ef5b00d816e51bfcc96c3539601fa48ef1c07e494bdc37054ba96ecb9dbd666417e3de289d4f424f502a982"
                ),
            ),
            (
                &q128[..],
                128,
                &hex!(
                    "ed6e8c036df90111410431431a232d41a32c86e296c05d426e5f44e75b9a50d335b2412bc6c91e0a6dc131de09c43110d9180d0a70f0d6289cb4e43b05f7ee5e9b3f42a1fad0f31bac6a625b3b5c50e3a83316783b649e5ecc9d3b1d9471cb5024b7ccf40d41d1751a04ca0356548bc6e703fca02ab521b505e8e45600508d32"
                ),
            ),
            (
                &a512[..],
                128,
                &hex!(
                    "78b53f2413f3c688f07732c10e5ced29a17c6a16f717179ffbe38d92d6c9ec296502eb9889af83a1928cd162e845b0d3c5424e83280fed3d10cffb2f8431f14e7a23f4c68819d40617589e4c41169d0b56e0e3535be1fd71fbb08bb70c5b5ffed953d6c14bf7618b35fc1f4c4b30538236b4b08c9fbf90462447a8ada60be495"
                ),
            ),
        ];
        for (message, size, uniform_bytes) in vectors {
            let mut output = [0u8; 128];
            Ristretto::<Field25519>::expand_message_xmd::<Sha256>(
                context,
                message,
                &mut output[..size],
            );
            assert_eq!(&output[..size], uniform_bytes);
        }
    }

    // https://www.rfc-editor.org/rfc/rfc9380#appendix-K.3
    #[test]
    fn test_expand_message_xmd_sha512() {
        let context = b"QUUX-V01-CS02-with-expander-SHA512-256";
        let q128 = padded::<133>(b"q128_", b'q');
        let a512 = padded::<517>(b"a512_", b'a');
        let vectors: [(&[u8], usize, &[u8]); 10] = [
            (
                b"",
                32,
                &hex!("6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba"),
            ),
            (
                b"abc",
                32,
                &hex!("0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc"),
            ),
            (
                b"abcdef0123456789",
                32,
                &hex!("087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58"),
            ),
            (
                &q128[..],
                32,
                &hex!("7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3"),
            ),
            (
                &a512[..],
                32,
                &hex!("57b5f7e766d5be68a6bfe1768e3c2b7f1228b3e4b3134956dd73a59b954c66f4"),
            ),
            (
                b"",
                128,
                &hex!(
                    "41b037d1734a5f8df225dd8c7de38f851efdb45c372887be655212d07251b921b052b62eaed99b46f72f2ef4cc96bfaf254ebbbec091e1a3b9e4fb5e5b619d2e0c5414800a1d882b62bb5cd1778f098b8eb6cb399d5d9d18f5d5842cf5d13d7eb00a7cff859b605da678b318bd0e65ebff70bec88c753b159a805d2c89c55961"
                ),
            ),
            (
                b"abc",
                128,
                &hex!(
                    "7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb1347ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b488431851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1"
                ),
            ),
            (
                b"abcdef0123456789",
                128,
                &hex!(
                    "3f721f208e6199fe903545abc26c837ce59ac6fa45733f1baaf0222f8b7acb0424814fcb5eecf6c1d38f06e9d0a6ccfbf85ae612ab8735dfdf9ce84c372a77c8f9e1c1e952c3a61b7567dd0693016af51d2745822663d0c2367e3f4f0bed827feecc2aaf98c949b5ed0d35c3f1023d64ad1407924288d366ea159f46287e61ac"
                ),
            ),
            (
                &q128[..],
                128,
                &hex!(
                    "b799b045a58c8d2b4334cf54b78260b45eec544f9f2fb5bd12fb603eaee70db7317bf807c406e26373922b7b8920fa29142703dd52bdf280084fb7ef69da78afdf80b3586395b433dc66cde048a258e476a561e9deba7060af40adf30c64249ca7ddea79806ee5beb9a1422949471d267b21bc88e688e4014087a0b592b695ed"
                ),
            ),
            (
                &a512[..],
                128,
                &hex!(
                    "05b0bfef265dcee87654372777b7c44177e2ae4c13a27f103340d9cd11c86cb2426ffcad5bd964080c2aee97f03be1ca18e30a1f14e27bc11ebbd650f305269cc9fb1db08bf90bfc79b42a952b46daf810359e7bc36452684784a64952c343c52e5124cd1f71d474d5197fefc571a92929c9084ffe1112cf5eea5192ebff330b"
                ),
            ),
        ];
        for (message, size, uniform_bytes) in vectors {
            let mut output = [0u8; 128];
            Ristretto::<Field25519>::expand_message_xmd::<Sha512>(
                context,
                message,
                &mut output[..size],
            );
            assert_eq!(&output[..size], uniform_bytes);
        }
    }

    // https://www.rfc-editor.org/rfc/rfc9497#appendix-A.1
    #[test]
    fn test_ristretto255_from_string() {
        let vectors = [
            (
                0,
                &hex!("00")[..],
                hex!("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
                hex!("609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c"),
            ),
            (
                0,
                &hex!("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")[..],
                hex!("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
                hex!("da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418"),
            ),
            (
                1,
                &hex!("00")[..],
                hex!("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
                hex!("863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945"),
            ),
            (
                1,
                &hex!("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")[..],
                hex!("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
                hex!("cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c"),
            ),
            (
                2,
                &hex!("00")[..],
                hex!("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
                hex!("c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715"),
            ),
            (
                2,
                &hex!("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a")[..],
                hex!("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
                hex!("f0f0b209dd4d5f1844dac679acc7761b91a2e704879656cb7c201e82a99ab07d"),
            ),
        ];
        for (mode, input, blind, blinded_element) in vectors {
            let mut context = *b"HashToGroup-OPRFV1-\x00-ristretto255-SHA512";
            context[19] = mode;
            let element = Ristretto255::from_string::<Sha512>(&context, input).unwrap();
            assert_eq!(
                Ristretto255::scalar_mult(&blind, &element).unwrap(),
                blinded_element
            );
        }
        assert_eq!(
            Ristretto255::from_string::<Sha512>(b"", b"message"),
            Err(Error::Misuse)
        );
    }

    #[test]
    fn test_ristretto255_scalar_complement() {
        let complement = Ristretto255::scalar_complement(&scalar(0)).unwrap();
        assert_eq!(
            Ristretto255::scalar_mult_base(&complement).unwrap(),
            MULTIPLES[1]
        );
        let complement = Ristretto255::scalar_complement(&scalar(2)).unwrap();
        assert_eq!(
            Ristretto255::scalar_mult_base(&complement).unwrap(),
            Ristretto255::sub(&MULTIPLES[0], &MULTIPLES[1]).unwrap()
        );
        assert_eq!(
            Ristretto255::scalar_complement(&ORDER),
            Err(Error::Encoding)
        );
    }
}
