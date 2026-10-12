use {
    crate::{
        Error,
        macs::Hmac,
        traits::{ByteArray, CryptoRng, Hasher, SeedableCryptoRng},
        utils::wipe,
    },
    core::array::TryFromSliceError,
};

pub struct HmacDrbg<H: Hasher> {
    k: H::Output,
    v: H::Output,
    reseed_counter: u64,
}

impl<H: Hasher> HmacDrbg<H> {
    pub fn new(seed: &H::Output) -> Self {
        Self::instantiate(seed.as_ref(), &[])
    }

    pub fn instantiate(entropy: &[u8], nonce: &[u8]) -> Self {
        let mut k = H::Output::new();
        let mut v = H::Output::new();
        k.as_mut().fill(0);
        v.as_mut().fill(1);
        let mut instance = Self {
            k,
            v,
            reseed_counter: 1,
        };
        instance.update(entropy, nonce);
        instance
    }

    pub fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        if self.reseed_counter > Self::RESEED_INTERVAL {
            return Err(Error::LimitExceeded);
        }
        for chunk in bytes.chunks_mut(H::OUTPUT_SIZE) {
            let mut mac = Hmac::<H>::new(self.k.as_ref());
            mac.update(self.v.as_ref());
            self.v = mac.finalize();
            chunk.copy_from_slice(&self.v.as_ref()[..chunk.len()]);
        }
        self.update(&[], &[]);
        self.reseed_counter += 1;
        Ok(())
    }
}

impl<H: Hasher> CryptoRng for HmacDrbg<H> {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.fill(bytes)
    }
}

impl<H: Hasher> SeedableCryptoRng for HmacDrbg<H> {}

impl<H: Hasher> TryFrom<&[u8]> for HmacDrbg<H> {
    type Error = TryFromSliceError;

    fn try_from(seed: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self::new(&H::Output::try_from_slice(seed)?))
    }
}

impl<H: Hasher> HmacDrbg<H> {
    const RESEED_INTERVAL: u64 = 1 << 48;

    fn update(&mut self, entropy: &[u8], nonce: &[u8]) {
        let mut mac = Hmac::<H>::new(self.k.as_ref());
        mac.update(self.v.as_ref());
        mac.update(&[0]);
        mac.update(entropy);
        mac.update(nonce);
        self.k = mac.finalize();
        let mut mac = Hmac::<H>::new(self.k.as_ref());
        mac.update(self.v.as_ref());
        self.v = mac.finalize();
        if entropy.is_empty() && nonce.is_empty() {
            return;
        }
        let mut mac = Hmac::<H>::new(self.k.as_ref());
        mac.update(self.v.as_ref());
        mac.update(&[1]);
        mac.update(entropy);
        mac.update(nonce);
        self.k = mac.finalize();
        let mut mac = Hmac::<H>::new(self.k.as_ref());
        mac.update(self.v.as_ref());
        self.v = mac.finalize();
    }
}

impl<H: Hasher> Drop for HmacDrbg<H> {
    fn drop(&mut self) {
        wipe(self.k.as_mut());
        wipe(self.v.as_mut());
    }
}
