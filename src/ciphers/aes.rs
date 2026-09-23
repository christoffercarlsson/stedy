use crate::traits::{SeekableStreamCipher, StreamCipher};

#[cfg_attr(target_arch = "aarch64", path = "aes/aarch64.rs")]
#[cfg_attr(target_arch = "x86_64", path = "aes/x86_64.rs")]
mod backend;

pub(crate) fn is_supported() -> bool {
    backend::is_supported()
}

pub(crate) fn multiply<const N: usize>(x: &[u128; N], h: &[u128; N]) -> u128 {
    unsafe { backend::multiply::<N>(x, h) }
}

fn encrypt_blocks<const ROUNDS: usize, const N: usize>(
    round_keys: &[[u8; 16]; 15],
    blocks: &[[u8; 16]; N],
    data: &mut [[u8; 16]; N],
) {
    unsafe {
        backend::encrypt_blocks::<ROUNDS, N>(round_keys, blocks, data);
    }
}

pub type Aes128Ctr = AesCtr<16>;
pub type Aes256Ctr = AesCtr<32>;

pub struct AesCtr<const KEY_SIZE: usize> {
    round_keys: [[u8; 16]; 15],
    nonce: [u8; 12],
    counter: u32,
    keystream: [u8; 16],
    offset: u8,
    wrap: bool,
}

impl<const KEY_SIZE: usize> AesCtr<KEY_SIZE> {
    pub fn is_supported() -> bool {
        is_supported()
    }

    pub fn new(key: &[u8; KEY_SIZE], nonce: &[u8; 12]) -> Self {
        assert!(
            is_supported(),
            "CPU supports AES and carry-less multiply instructions"
        );
        Self {
            round_keys: Self::expand_key(key),
            nonce: *nonce,
            counter: 1,
            keystream: [0u8; 16],
            offset: 16,
            wrap: false,
        }
    }

    pub fn apply_keystream(&mut self, mut data: &mut [u8]) {
        while !data.is_empty() {
            if self.offset == 16 && data.len() >= 128 && self.is_batchable() {
                let (head, tail) = data.split_at_mut(128);
                self.next_blocks(head);
                data = tail;
                continue;
            }
            if self.offset == 16 {
                self.next();
            }
            let offset = self.offset as usize;
            let take = data.len().min(16 - offset);
            let keystream = &self.keystream[offset..offset + take];
            let (head, tail) = data.split_at_mut(take);
            for (b, k) in head.iter_mut().zip(keystream.iter()) {
                *b ^= k;
            }
            self.offset += take as u8;
            data = tail;
        }
    }

    pub fn seek(&mut self, counter: u32) {
        self.counter = counter;
        self.offset = 16;
    }
}

impl<const KEY_SIZE: usize> StreamCipher for AesCtr<KEY_SIZE> {
    const KEY_SIZE: usize = KEY_SIZE;
    const NONCE_SIZE: usize = 12;

    type Key = [u8; KEY_SIZE];
    type Nonce = [u8; 12];

    fn new(key: &Self::Key, nonce: &Self::Nonce) -> Self {
        Self::new(key, nonce)
    }

    fn apply_keystream(&mut self, message: &mut [u8]) {
        self.apply_keystream(message);
    }
}

macro_rules! impl_seekable_stream_cipher {
    ($($key_size:literal),*) => {
        $(
            impl SeekableStreamCipher for AesCtr<$key_size> {
                const SEED_SIZE: usize = $key_size + 16;

                type Seed = [u8; Self::SEED_SIZE];

                fn seed(seed: &Self::Seed) -> Self {
                    Self::from_seed(seed)
                }

                fn seek(&mut self, counter: u32) {
                    self.seek(counter);
                }
            }
        )*
    };
}

impl_seekable_stream_cipher!(16, 32);

impl<const KEY_SIZE: usize> AesCtr<KEY_SIZE> {
    const ROUNDS: usize = KEY_SIZE / 4 + 6;

    pub(crate) fn hash_subkey(&self) -> [u8; 16] {
        self.encrypt_block([0u8; 16])
    }

    fn from_seed(seed: &[u8]) -> Self {
        let (key, remaining) = seed.split_at(KEY_SIZE);
        let (nonce, counter) = remaining.split_at(12);
        let key = <&[u8; KEY_SIZE]>::try_from(key).expect("AES key fits within the seed");
        let nonce = <&[u8; 12]>::try_from(nonce).expect("AES nonce fits within the seed");
        let counter = <&[u8; 4]>::try_from(counter).expect("AES counter fits within the seed");
        let counter = u32::from_be_bytes(*counter);
        let mut cipher = Self::new(key, nonce);
        cipher.seek(counter);
        cipher.wrap = true;
        cipher
    }

    fn encrypt_block(&self, block: [u8; 16]) -> [u8; 16] {
        let mut data = [[0u8; 16]];
        self.encrypt_blocks(&[block], &mut data);
        data[0]
    }

    fn encrypt_blocks<const N: usize>(&self, blocks: &[[u8; 16]; N], data: &mut [[u8; 16]; N]) {
        let keys = &self.round_keys;
        match KEY_SIZE {
            16 => encrypt_blocks::<10, N>(keys, blocks, data),
            _ => encrypt_blocks::<14, N>(keys, blocks, data),
        }
    }

    fn counter_block(&self, counter: u32) -> [u8; 16] {
        let mut block = [0u8; 16];
        block[..12].copy_from_slice(&self.nonce);
        block[12..].copy_from_slice(&counter.to_be_bytes());
        block
    }

    fn next(&mut self) {
        assert!(
            self.wrap || self.counter != 0,
            "AES-GCM message limit not exceeded"
        );
        self.keystream = self.encrypt_block(self.counter_block(self.counter));
        self.counter = self.counter.wrapping_add(1);
        self.offset = 0;
    }

    fn is_batchable(&self) -> bool {
        self.wrap || (self.counter != 0 && self.counter.checked_add(7).is_some())
    }

    fn next_blocks(&mut self, data: &mut [u8]) {
        let mut blocks = [[0u8; 16]; 8];
        for (i, block) in blocks.iter_mut().enumerate() {
            *block = self.counter_block(self.counter.wrapping_add(i as u32));
        }
        let (chunks, _) = data.as_chunks_mut::<16>();
        let chunks = chunks.try_into().expect("a batch holds 8 blocks");
        self.encrypt_blocks(&blocks, chunks);
        self.counter = self.counter.wrapping_add(8);
    }

    fn expand_key(key: &[u8; KEY_SIZE]) -> [[u8; 16]; 15] {
        let nk = KEY_SIZE / 4;
        let mut words = [0u32; 60];
        let (chunks, _) = key.as_chunks::<4>();
        for (i, chunk) in chunks.iter().enumerate() {
            words[i] = u32::from_le_bytes(*chunk);
        }
        let mut rcon = 1u8;
        for i in nk..4 * (Self::ROUNDS + 1) {
            let mut temp = words[i - 1];
            if i % nk == 0 {
                temp = Self::sub_word(temp.rotate_right(8)) ^ rcon as u32;
                rcon = (rcon << 1) ^ (0x1b & (rcon >> 7).wrapping_neg());
            } else if nk > 6 && i % nk == 4 {
                temp = Self::sub_word(temp);
            }
            words[i] = words[i - nk] ^ temp;
        }
        let mut round_keys = [[0u8; 16]; 15];
        let (chunks, _) = words.as_chunks::<4>();
        for (i, chunk) in chunks.iter().enumerate() {
            let (bytes, _) = round_keys[i].as_chunks_mut::<4>();
            for (j, b) in bytes.iter_mut().enumerate() {
                b.copy_from_slice(&chunk[j].to_le_bytes());
            }
        }
        round_keys
    }

    #[inline(always)]
    fn sub_word(word: u32) -> u32 {
        let mut block = [0u8; 16];
        let (chunks, _) = block.as_chunks_mut::<4>();
        for chunk in chunks.iter_mut() {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        let mut data = [[0u8; 16]];
        encrypt_blocks::<1, 1>(&[[0u8; 16]; 15], &[block], &mut data);
        u32::from_le_bytes([data[0][0], data[0][1], data[0][2], data[0][3]])
    }
}
