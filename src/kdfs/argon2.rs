#[cfg(feature = "std")]
use {crate::utils::wipe, std::thread};
use {
    crate::{
        encoding::{decode, encode, Encoding},
        hashes::{Blake2b512, Blake2bVar},
        utils::{verify, Secret},
    },
    core::ops::{BitXorAssign, Index, IndexMut},
};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argon2Variant {
    Argon2d = 0,
    Argon2i = 1,
    Argon2id = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    variant: Argon2Variant,
    memory: u32,
    passes: u32,
    lanes: u32,
    threads: u32,
}

impl Argon2Params {
    pub fn new(variant: Argon2Variant) -> Self {
        Self {
            variant,
            memory: 1 << 16,
            passes: 3,
            lanes: 4,
            threads: 4,
        }
    }

    pub fn variant(mut self, variant: Argon2Variant) -> Self {
        self.variant = variant;
        self
    }

    pub fn memory(mut self, memory: u32) -> Self {
        self.memory = memory;
        self
    }

    pub fn passes(mut self, passes: u32) -> Self {
        self.passes = passes;
        self
    }

    pub fn lanes(mut self, lanes: u32) -> Self {
        self.lanes = lanes;
        self
    }

    pub fn threads(mut self, threads: u32) -> Self {
        self.threads = threads;
        self
    }

    pub fn blocks(&self) -> usize {
        let lanes = self.lanes as usize;
        if lanes == 0 {
            return 0;
        }
        (self.memory as usize) / (Self::SLICES * lanes) * Self::SLICES * lanes
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::new(Argon2Variant::Argon2id)
    }
}

#[derive(Clone, Copy)]
pub struct Argon2Block([u64; Self::WORDS]);

impl Argon2Block {
    pub const ZERO: Self = Self([0; Self::WORDS]);
}

impl Default for Argon2Block {
    fn default() -> Self {
        Self::ZERO
    }
}

#[cfg(feature = "std")]
pub fn argon2(
    params: Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: Option<&[u8]>,
    associated_data: Option<&[u8]>,
    output: &mut [u8],
) -> bool {
    if !params.validate(
        password,
        salt,
        secret.unwrap_or_default(),
        associated_data.unwrap_or_default(),
        output,
    ) {
        return false;
    }
    let mut memory = Argon2Memory(vec![Argon2Block::ZERO; params.blocks()]);
    argon2_with_memory(
        params,
        password,
        salt,
        secret,
        associated_data,
        &mut memory.0,
        output,
    )
}

pub fn argon2_with_memory(
    params: Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: Option<&[u8]>,
    associated_data: Option<&[u8]>,
    memory: &mut [Argon2Block],
    output: &mut [u8],
) -> bool {
    let secret = secret.unwrap_or_default();
    let associated_data = associated_data.unwrap_or_default();
    if !params.validate(password, salt, secret, associated_data, output)
        || memory.len() < params.blocks()
    {
        return false;
    }
    let memory = &mut memory[..params.blocks()];
    let h0 = params.initial_hash(password, salt, secret, associated_data, output);
    params.fill_first_blocks(memory, h0.get());
    params.fill_memory(memory);
    params.calculate_output(memory, output);
    true
}

#[cfg(feature = "std")]
pub fn argon2_phc<'a>(
    params: Argon2Params,
    password: &[u8],
    salt: &[u8],
    hash_length: usize,
    output: &'a mut [u8],
) -> Option<&'a [u8]> {
    if !params.validate(password, salt, &[], &[], &[0; 4]) {
        return None;
    }
    let mut memory = Argon2Memory(vec![Argon2Block::ZERO; params.blocks()]);
    argon2_phc_with_memory(params, password, salt, hash_length, &mut memory.0, output)
}

pub fn argon2_phc_with_memory<'a>(
    params: Argon2Params,
    password: &[u8],
    salt: &[u8],
    hash_length: usize,
    memory: &mut [Argon2Block],
    output: &'a mut [u8],
) -> Option<&'a [u8]> {
    if !(4..=Argon2Params::PHC_HASH_SIZE).contains(&hash_length)
        || salt.len() > Argon2Params::PHC_SALT_SIZE
    {
        return None;
    }
    let mut hash = [0u8; Argon2Params::PHC_HASH_SIZE];
    let hash = &mut hash[..hash_length];
    if !argon2_with_memory(params, password, salt, None, None, memory, hash) {
        return None;
    }
    params.encode_phc(salt, hash, output)
}

#[cfg(feature = "std")]
pub fn argon2_phc_verify(password: &[u8], phc: &[u8]) -> bool {
    let Some((params, _, _)) = Argon2Params::parse_phc(phc) else {
        return false;
    };
    let mut blocks = Vec::new();
    if blocks.try_reserve_exact(params.blocks()).is_err() {
        return false;
    }
    blocks.resize(params.blocks(), Argon2Block::ZERO);
    let mut memory = Argon2Memory(blocks);
    argon2_phc_verify_with_memory(password, phc, &mut memory.0)
}

pub fn argon2_phc_verify_with_memory(
    password: &[u8],
    phc: &[u8],
    memory: &mut [Argon2Block],
) -> bool {
    let Some((params, salt, hash)) = Argon2Params::parse_phc(phc) else {
        return false;
    };
    let mut salt_bytes = [0u8; Argon2Params::PHC_SALT_SIZE];
    let Some(salt) = decode(Encoding::Base64Unpadded, salt, &mut salt_bytes) else {
        return false;
    };
    let mut hash_bytes = [0u8; Argon2Params::PHC_HASH_SIZE];
    let Some(expected) = decode(Encoding::Base64Unpadded, hash, &mut hash_bytes) else {
        return false;
    };
    let mut computed = [0u8; Argon2Params::PHC_HASH_SIZE];
    let computed = &mut computed[..expected.len()];
    argon2_with_memory(params, password, salt, None, None, memory, computed)
        && verify(computed, expected)
}

impl Argon2Params {
    const SLICES: usize = 4;
    const VERSION: u32 = 0x13;
    const MAX_INPUT_SIZE: u64 = u32::MAX as u64;

    fn validate(
        &self,
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        associated_data: &[u8],
        output: &[u8],
    ) -> bool {
        if self.lanes == 0
            || self.lanes >= 1 << 24
            || self.memory / 8 < self.lanes
            || self.passes == 0
            || self.threads == 0
            || salt.len() < 8
            || output.len() < 4
        {
            return false;
        }
        if password.len() as u64 > Self::MAX_INPUT_SIZE
            || salt.len() as u64 > Self::MAX_INPUT_SIZE
            || secret.len() as u64 > Self::MAX_INPUT_SIZE
            || associated_data.len() as u64 > Self::MAX_INPUT_SIZE
            || output.len() as u64 > Self::MAX_INPUT_SIZE
        {
            return false;
        }
        true
    }

    fn lane_length(&self) -> usize {
        self.blocks() / self.lanes as usize
    }

    fn segment_length(&self) -> usize {
        self.lane_length() / Self::SLICES
    }

    fn initial_hash(
        &self,
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        associated_data: &[u8],
        output: &[u8],
    ) -> Secret<[u8; 64]> {
        let mut hasher = Blake2b512::new(None);
        hasher.update(&self.lanes.to_le_bytes());
        hasher.update(&(output.len() as u32).to_le_bytes());
        hasher.update(&self.memory.to_le_bytes());
        hasher.update(&self.passes.to_le_bytes());
        hasher.update(&Self::VERSION.to_le_bytes());
        hasher.update(&(self.variant as u32).to_le_bytes());
        hasher.update(&(password.len() as u32).to_le_bytes());
        hasher.update(password);
        hasher.update(&(salt.len() as u32).to_le_bytes());
        hasher.update(salt);
        hasher.update(&(secret.len() as u32).to_le_bytes());
        hasher.update(secret);
        hasher.update(&(associated_data.len() as u32).to_le_bytes());
        hasher.update(associated_data);
        Secret::from(hasher.finalize())
    }

    fn fill_first_blocks(&self, memory: &mut [Argon2Block], h0: &[u8; 64]) {
        let lane_length = self.lane_length();
        let mut bytes = Secret::from([0u8; Argon2Block::SIZE]);
        for lane in 0..self.lanes {
            for column in 0u32..2 {
                Self::hash_variable(
                    &[h0, &column.to_le_bytes(), &lane.to_le_bytes()],
                    bytes.get_mut(),
                );
                memory[(lane as usize) * lane_length + column as usize] =
                    Argon2Block::from_bytes(bytes.get());
            }
        }
    }

    fn fill_memory(&self, memory: &mut [Argon2Block]) {
        #[cfg(feature = "std")]
        if self.threads > 1 {
            return self.fill_memory_parallel(memory);
        }
        let lanes = self.lanes as usize;
        let passes = self.passes as usize;
        let segment_length = self.segment_length();
        for pass in 0..passes {
            for slice in 0..Self::SLICES {
                for lane in 0..lanes {
                    let segment_index = lane * Self::SLICES + slice;
                    let (before, rest) = memory.split_at_mut(segment_index * segment_length);
                    let (current, after) = rest.split_at_mut(segment_length);
                    let mut view = Argon2Segment {
                        segment_length,
                        segment_index,
                        current,
                        reference_area: Argon2ReferenceArea::Split { before, after },
                    };
                    self.fill_segment(&mut view, pass, lane, slice);
                }
            }
        }
    }

    #[cfg(feature = "std")]
    fn fill_memory_parallel(&self, memory: &mut [Argon2Block]) {
        let lanes = self.lanes as usize;
        let passes = self.passes as usize;
        let threads = (self.threads as usize).min(lanes);
        let segment_length = self.segment_length();
        for pass in 0..passes {
            for slice in 0..Self::SLICES {
                let mut current = Vec::with_capacity(lanes);
                let mut finished = Vec::with_capacity(lanes * Self::SLICES);
                for (i, segment) in memory.chunks_mut(segment_length).enumerate() {
                    if i % Self::SLICES == slice {
                        finished.push(None);
                        current.push(segment);
                    } else {
                        finished.push(Some(&*segment));
                    }
                }
                for (batch, segments) in current.chunks_mut(threads).enumerate() {
                    thread::scope(|scope| {
                        for (i, segment) in segments.iter_mut().enumerate() {
                            let lane = batch * threads + i;
                            let mut view = Argon2Segment {
                                segment_length,
                                segment_index: lane * Self::SLICES + slice,
                                current: segment,
                                reference_area: Argon2ReferenceArea::Finished(&finished),
                            };
                            scope.spawn(move || self.fill_segment(&mut view, pass, lane, slice));
                        }
                    });
                }
            }
        }
    }

    fn fill_segment(&self, view: &mut Argon2Segment<'_>, pass: usize, lane: usize, slice: usize) {
        let segment_length = self.segment_length();
        let lane_length = self.lane_length();
        let data_independent = self.is_data_independent(pass, slice);
        let mut addresses = Secret::from(Argon2Block::ZERO);
        let mut block = Secret::from(Argon2Block::ZERO);
        let mut input = self.address_input(pass, lane, slice);
        let start = if pass == 0 && slice == 0 { 2 } else { 0 };
        let first = lane * lane_length + slice * segment_length;
        for index in start..segment_length {
            let current = first + index;
            let previous = if index == 0 && slice == 0 {
                current + lane_length - 1
            } else {
                current - 1
            };
            let j = if data_independent {
                Self::next_address(&mut addresses, &mut input, start, index)
            } else {
                view.block(previous)[0]
            };
            let reference = self.reference_block(j, pass, lane, slice, index);
            Argon2Block::compress(view.block(previous), view.block(reference), block.get_mut());
            let destination = view.block_mut(current);
            if pass == 0 {
                *destination = *block.get();
            } else {
                *destination ^= block.get();
            }
        }
    }

    fn is_data_independent(&self, pass: usize, slice: usize) -> bool {
        match self.variant {
            Argon2Variant::Argon2d => false,
            Argon2Variant::Argon2i => true,
            Argon2Variant::Argon2id => pass == 0 && slice < Self::SLICES / 2,
        }
    }

    fn address_input(&self, pass: usize, lane: usize, slice: usize) -> Argon2Block {
        let mut input = Argon2Block::ZERO;
        input[0] = pass as u64;
        input[1] = lane as u64;
        input[2] = slice as u64;
        input[3] = self.blocks() as u64;
        input[4] = self.passes as u64;
        input[5] = self.variant as u64;
        input
    }

    fn next_address(
        addresses: &mut Secret<Argon2Block>,
        input: &mut Argon2Block,
        start: usize,
        index: usize,
    ) -> u64 {
        if index == start || index.is_multiple_of(Argon2Block::WORDS) {
            input[6] += 1;
            let mut first = Secret::from(Argon2Block::ZERO);
            Argon2Block::compress(&Argon2Block::ZERO, input, first.get_mut());
            Argon2Block::compress(&Argon2Block::ZERO, first.get(), addresses.get_mut());
        }
        addresses[index % Argon2Block::WORDS]
    }

    fn reference_block(
        &self,
        j: u64,
        pass: usize,
        lane: usize,
        slice: usize,
        index: usize,
    ) -> usize {
        let lanes = self.lanes as usize;
        let j1 = j as u32;
        let j2 = (j >> 32) as u32;
        let reference_lane = if pass == 0 && slice == 0 {
            lane
        } else {
            (j2 as usize) % lanes
        };
        let reference = self.reference_index(pass, slice, index, j1, reference_lane == lane);
        reference_lane * self.lane_length() + reference
    }

    fn reference_index(
        &self,
        pass: usize,
        slice: usize,
        index: usize,
        j1: u32,
        same_lane: bool,
    ) -> usize {
        let segment_length = self.segment_length();
        let lane_length = self.lane_length();
        let mut area = if pass == 0 {
            slice * segment_length
        } else {
            lane_length - segment_length
        };
        if same_lane {
            area += index;
        }
        if same_lane || index == 0 {
            area -= 1;
        }
        let x = ((j1 as u64) * (j1 as u64)) >> 32;
        let y = ((area as u64) * x) >> 32;
        let z = area - 1 - y as usize;
        let start = if pass == 0 || slice == Self::SLICES - 1 {
            0
        } else {
            (slice + 1) * segment_length
        };
        (start + z) % lane_length
    }

    fn calculate_output(&self, memory: &[Argon2Block], output: &mut [u8]) {
        let lanes = self.lanes as usize;
        let lane_length = self.lane_length();
        let mut c = Secret::from(memory[lane_length - 1]);
        for lane in 1..lanes {
            *c.get_mut() ^= &memory[lane * lane_length + lane_length - 1];
        }
        let bytes = Secret::from(c.get().to_bytes());
        Self::hash_variable(&[bytes.as_ref()], output);
    }

    fn hash_variable(inputs: &[&[u8]], output: &mut [u8]) {
        if output.len() <= 64 {
            Self::hash_prefixed(inputs, output.len(), output);
            return;
        }
        let mut v = Secret::<[u8; 64]>::from([0u8; 64]);
        Self::hash_prefixed(inputs, output.len(), v.get_mut());
        let halves = (output.len() - 33) / 32;
        let (head, tail) = output.split_at_mut(32 * halves);
        for (i, chunk) in head.chunks_mut(32).enumerate() {
            if i > 0 {
                v = Secret::from(Blake2b512::digest(v.as_ref()));
            }
            chunk.copy_from_slice(&v[..32]);
        }
        let mut hasher = Blake2bVar::new(None, tail.len()).expect("H' digest length is 1 to 64");
        hasher.update(v.as_ref());
        hasher.finalize_into(tail);
    }

    fn hash_prefixed(inputs: &[&[u8]], length: usize, digest: &mut [u8]) {
        let mut hasher = Blake2bVar::new(None, digest.len()).expect("H' digest length is 1 to 64");
        hasher.update(&(length as u32).to_le_bytes());
        for input in inputs {
            hasher.update(input);
        }
        hasher.finalize_into(digest);
    }

    const PHC_SALT_SIZE: usize = 64;
    const PHC_HASH_SIZE: usize = 64;

    fn parse_phc(phc: &[u8]) -> Option<(Self, &[u8], &[u8])> {
        let mut fields = phc.strip_prefix(b"$")?.split(|&byte| byte == b'$');
        let variant = match fields.next()? {
            b"argon2d" => Argon2Variant::Argon2d,
            b"argon2i" => Argon2Variant::Argon2i,
            b"argon2id" => Argon2Variant::Argon2id,
            _ => return None,
        };
        if Self::decimal(fields.next()?.strip_prefix(b"v=")?)? != Self::VERSION {
            return None;
        }
        let mut costs = fields.next()?.split(|&byte| byte == b',');
        let memory = Self::decimal(costs.next()?.strip_prefix(b"m=")?)?;
        let passes = Self::decimal(costs.next()?.strip_prefix(b"t=")?)?;
        let lanes = Self::decimal(costs.next()?.strip_prefix(b"p=")?)?;
        if costs.next().is_some() {
            return None;
        }
        let salt = fields.next()?;
        let hash = fields.next()?;
        if fields.next().is_some() || salt.contains(&b'=') || hash.contains(&b'=') {
            return None;
        }
        let params = Self::new(variant)
            .memory(memory)
            .passes(passes)
            .lanes(lanes);
        Some((params, salt, hash))
    }

    fn encode_phc<'a>(&self, salt: &[u8], hash: &[u8], output: &'a mut [u8]) -> Option<&'a [u8]> {
        let variant: &[u8] = match self.variant {
            Argon2Variant::Argon2d => b"argon2d",
            Argon2Variant::Argon2i => b"argon2i",
            Argon2Variant::Argon2id => b"argon2id",
        };
        let mut writer = PhcWriter { output, length: 0 };
        writer.bytes(b"$")?;
        writer.bytes(variant)?;
        writer.bytes(b"$v=")?;
        writer.decimal(Self::VERSION)?;
        writer.bytes(b"$m=")?;
        writer.decimal(self.memory)?;
        writer.bytes(b",t=")?;
        writer.decimal(self.passes)?;
        writer.bytes(b",p=")?;
        writer.decimal(self.lanes)?;
        writer.bytes(b"$")?;
        writer.base64(salt)?;
        writer.bytes(b"$")?;
        writer.base64(hash)?;
        Some(writer.finish())
    }

    fn decimal(digits: &[u8]) -> Option<u32> {
        if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
            return None;
        }
        let mut value: u32 = 0;
        for &digit in digits {
            if !digit.is_ascii_digit() {
                return None;
            }
            value = value
                .checked_mul(10)?
                .checked_add(u32::from(digit - b'0'))?;
        }
        Some(value)
    }
}

struct PhcWriter<'a> {
    output: &'a mut [u8],
    length: usize,
}

impl<'a> PhcWriter<'a> {
    fn bytes(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.length.checked_add(bytes.len())?;
        self.output
            .get_mut(self.length..end)?
            .copy_from_slice(bytes);
        self.length = end;
        Some(())
    }

    fn decimal(&mut self, mut value: u32) -> Option<()> {
        let mut digits = [0u8; 10];
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.bytes(&digits[start..])
    }

    fn base64(&mut self, bytes: &[u8]) -> Option<()> {
        let written = encode(
            Encoding::Base64Unpadded,
            bytes,
            &mut self.output[self.length..],
        )?
        .len();
        self.length += written;
        Some(())
    }

    fn finish(self) -> &'a [u8] {
        &self.output[..self.length]
    }
}

struct Argon2Segment<'a> {
    segment_length: usize,
    segment_index: usize,
    current: &'a mut [Argon2Block],
    reference_area: Argon2ReferenceArea<'a>,
}

enum Argon2ReferenceArea<'a> {
    Split {
        before: &'a [Argon2Block],
        after: &'a [Argon2Block],
    },
    #[cfg(feature = "std")]
    Finished(&'a [Option<&'a [Argon2Block]>]),
}

impl Argon2Segment<'_> {
    fn block(&self, index: usize) -> &Argon2Block {
        let segment = index / self.segment_length;
        let offset = index % self.segment_length;
        if segment == self.segment_index {
            return &self.current[offset];
        }
        match self.reference_area {
            Argon2ReferenceArea::Split { before, after } => {
                if segment < self.segment_index {
                    &before[index]
                } else {
                    &after[index - (self.segment_index + 1) * self.segment_length]
                }
            }
            #[cfg(feature = "std")]
            Argon2ReferenceArea::Finished(finished) => {
                let segment = finished[segment].expect("in-progress segments are never referenced");
                &segment[offset]
            }
        }
    }

    fn block_mut(&mut self, index: usize) -> &mut Argon2Block {
        &mut self.current[index % self.segment_length]
    }
}

#[cfg(feature = "std")]
struct Argon2Memory(Vec<Argon2Block>);

#[cfg(feature = "std")]
impl Drop for Argon2Memory {
    fn drop(&mut self) {
        for block in self.0.iter_mut() {
            wipe(&mut block.0);
        }
    }
}

impl Argon2Block {
    const WORDS: usize = 128;
    const SIZE: usize = Self::WORDS * 8;
    const MASK: u64 = (1 << 32) - 1;

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let mut block = Self::ZERO;
        let (chunks, _) = bytes.as_chunks::<8>();
        for (i, chunk) in chunks.iter().enumerate() {
            block[i] = u64::from_le_bytes(*chunk);
        }
        block
    }

    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        let (chunks, _) = bytes.as_chunks_mut::<8>();
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk.copy_from_slice(&self[i].to_le_bytes());
        }
        bytes
    }

    fn compress(x: &Self, y: &Self, q: &mut Self) {
        q.0 = x.0;
        *q ^= y;
        let (chunks, _) = q.0.as_chunks_mut::<16>();
        for chunk in chunks {
            Self::permute(chunk);
        }
        let mut v = Secret::from([0u64; 16]);
        for column in 0..8 {
            for k in 0..8 {
                v[2 * k] = q[16 * k + 2 * column];
                v[2 * k + 1] = q[16 * k + 2 * column + 1];
            }
            Self::permute(v.get_mut());
            for k in 0..8 {
                q[16 * k + 2 * column] = v[2 * k];
                q[16 * k + 2 * column + 1] = v[2 * k + 1];
            }
        }
        *q ^= x;
        *q ^= y;
    }

    fn permute(v: &mut [u64; 16]) {
        Self::g(v, 0, 4, 8, 12);
        Self::g(v, 1, 5, 9, 13);
        Self::g(v, 2, 6, 10, 14);
        Self::g(v, 3, 7, 11, 15);
        Self::g(v, 0, 5, 10, 15);
        Self::g(v, 1, 6, 11, 12);
        Self::g(v, 2, 7, 8, 13);
        Self::g(v, 3, 4, 9, 14);
    }

    #[inline(always)]
    fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
        v[a] = Self::mix(v[a], v[b]);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = Self::mix(v[c], v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = Self::mix(v[a], v[b]);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = Self::mix(v[c], v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    }

    #[inline(always)]
    fn mix(a: u64, b: u64) -> u64 {
        a.wrapping_add(b)
            .wrapping_add(((a & Self::MASK) * (b & Self::MASK)) << 1)
    }
}

impl Index<usize> for Argon2Block {
    type Output = u64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Argon2Block {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl BitXorAssign<&Argon2Block> for Argon2Block {
    fn bitxor_assign(&mut self, rhs: &Self) {
        for (a, b) in self.0.iter_mut().zip(&rhs.0) {
            *a ^= b;
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    // https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c

    #[test]
    fn test_argon2_phc() {
        let vectors: [(Argon2Variant, u32, &[u8]); 4] = [
            (
                Argon2Variant::Argon2i,
                1,
                b"$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8",
            ),
            (
                Argon2Variant::Argon2i,
                2,
                b"$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E",
            ),
            (
                Argon2Variant::Argon2id,
                1,
                b"$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
            ),
            (
                Argon2Variant::Argon2id,
                2,
                b"$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc",
            ),
        ];
        let mut memory = [Argon2Block::ZERO; 256];
        for (variant, lanes, expected) in vectors {
            let params = Argon2Params::new(variant)
                .memory(256)
                .passes(2)
                .lanes(lanes);
            assert_eq!(
                Argon2Params::parse_phc(expected).map(|(parsed, _, _)| parsed),
                Some(params)
            );
            let mut output = [0u8; 128];
            let encoded = argon2_phc_with_memory(
                params.threads(1),
                b"password",
                b"somesalt",
                32,
                &mut memory,
                &mut output,
            )
            .unwrap();
            assert_eq!(encoded, expected);
            assert!(argon2_phc_verify_with_memory(
                b"password",
                expected,
                &mut memory
            ));
            assert!(!argon2_phc_verify_with_memory(
                b"Password",
                expected,
                &mut memory
            ));
            assert!(!argon2_phc_verify_with_memory(
                b"password",
                &expected[..expected.len() - 1],
                &mut memory
            ));
            #[cfg(feature = "std")]
            {
                let mut output = [0u8; 128];
                let encoded =
                    argon2_phc(params, b"password", b"somesalt", 32, &mut output).unwrap();
                assert_eq!(encoded, expected);
                assert!(argon2_phc_verify(b"password", expected));
                assert!(!argon2_phc_verify(b"Password", expected));
            }
        }
        let rejected: [&[u8]; 8] = [
            b"",
            b"$argon2x$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
            b"$argon2id$v=16$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
            b"$argon2id$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
            b"$argon2id$v=19$m=0256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
            b"$argon2id$v=19$m=256,t=2,p=1,keyid=AAAA$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
            b"$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4$",
            b"$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4=",
        ];
        for phc in rejected {
            assert!(Argon2Params::parse_phc(phc).is_none());
            assert!(!argon2_phc_verify_with_memory(
                b"password",
                phc,
                &mut memory
            ));
        }
    }

    // https://datatracker.ietf.org/doc/html/rfc9106#section-5

    #[test]
    fn test_argon2d() {
        let params = Argon2Params::new(Argon2Variant::Argon2d).memory(32);
        let password = [1u8; 32];
        let salt = [2u8; 16];
        let secret = [3u8; 8];
        let associated_data = [4u8; 12];
        let mut memory = [Argon2Block::ZERO; 32];
        let mut output = [0u8; 32];
        assert!(argon2_with_memory(
            params.threads(1),
            &password,
            &salt,
            Some(&secret),
            Some(&associated_data),
            &mut memory,
            &mut output,
        ));
        #[cfg(feature = "std")]
        {
            let mut parallel = [0u8; 32];
            assert!(argon2(
                params,
                &password,
                &salt,
                Some(&secret),
                Some(&associated_data),
                &mut parallel,
            ));
            assert_eq!(parallel, output);
        }
        assert_eq!(
            output,
            hex!("512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")
        );
    }

    #[test]
    fn test_argon2i() {
        let params = Argon2Params::new(Argon2Variant::Argon2i).memory(32);
        let password = [1u8; 32];
        let salt = [2u8; 16];
        let secret = [3u8; 8];
        let associated_data = [4u8; 12];
        let mut memory = [Argon2Block::ZERO; 32];
        let mut output = [0u8; 32];
        assert!(argon2_with_memory(
            params.threads(1),
            &password,
            &salt,
            Some(&secret),
            Some(&associated_data),
            &mut memory,
            &mut output,
        ));
        #[cfg(feature = "std")]
        {
            let mut parallel = [0u8; 32];
            assert!(argon2(
                params,
                &password,
                &salt,
                Some(&secret),
                Some(&associated_data),
                &mut parallel,
            ));
            assert_eq!(parallel, output);
        }
        assert_eq!(
            output,
            hex!("c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")
        );
    }

    #[test]
    fn test_argon2id() {
        let params = Argon2Params::default().memory(32);
        let password = [1u8; 32];
        let salt = [2u8; 16];
        let secret = [3u8; 8];
        let associated_data = [4u8; 12];
        let mut memory = [Argon2Block::ZERO; 32];
        let mut output = [0u8; 32];
        assert!(argon2_with_memory(
            params.threads(1),
            &password,
            &salt,
            Some(&secret),
            Some(&associated_data),
            &mut memory,
            &mut output,
        ));
        #[cfg(feature = "std")]
        {
            let mut parallel = [0u8; 32];
            assert!(argon2(
                params,
                &password,
                &salt,
                Some(&secret),
                Some(&associated_data),
                &mut parallel,
            ));
            assert_eq!(parallel, output);
        }
        assert_eq!(
            output,
            hex!("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }
}
