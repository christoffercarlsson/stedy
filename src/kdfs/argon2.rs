use {
    crate::hashes::{Blake2b512, Blake2bVar},
    core::ops::{BitXorAssign, Index, IndexMut},
    std::thread,
};

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argon2Variant {
    Argon2d = 0,
    Argon2i = 1,
    Argon2id = 2,
}

#[derive(Clone, Copy)]
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
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::new(Argon2Variant::Argon2id)
    }
}

pub fn argon2(
    params: Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: Option<&[u8]>,
    associated_data: Option<&[u8]>,
    output: &mut [u8],
) -> bool {
    let secret = secret.unwrap_or_default();
    let associated_data = associated_data.unwrap_or_default();
    if params.lanes == 0
        || params.lanes >= 1 << 24
        || params.memory / 8 < params.lanes
        || params.passes == 0
        || params.threads == 0
        || salt.len() < 8
        || output.len() < 4
    {
        return false;
    }
    if password.len() as u64 > Argon2Params::MAX_INPUT_SIZE
        || salt.len() as u64 > Argon2Params::MAX_INPUT_SIZE
        || secret.len() as u64 > Argon2Params::MAX_INPUT_SIZE
        || associated_data.len() as u64 > Argon2Params::MAX_INPUT_SIZE
        || output.len() as u64 > Argon2Params::MAX_INPUT_SIZE
    {
        return false;
    }
    let h0 = params.initial_hash(password, salt, secret, associated_data, output);
    let mut memory = vec![Argon2Block::ZERO; params.blocks()];
    params.fill_first_blocks(&mut memory, &h0);
    params.fill_memory(&mut memory);
    params.calculate_output(&memory, output);
    true
}

impl Argon2Params {
    const SLICES: usize = 4;
    const VERSION: u32 = 0x13;
    const MAX_INPUT_SIZE: u64 = u32::MAX as u64;

    fn blocks(&self) -> usize {
        let lanes = self.lanes as usize;
        (self.memory as usize) / (Self::SLICES * lanes) * Self::SLICES * lanes
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
    ) -> [u8; 64] {
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
        hasher.finalize()
    }

    fn fill_first_blocks(&self, memory: &mut [Argon2Block], h0: &[u8; 64]) {
        let lane_length = self.lane_length();
        let mut bytes = [0u8; Argon2Block::SIZE];
        for lane in 0..self.lanes {
            for column in 0u32..2 {
                Self::hash_variable(
                    &[h0, &column.to_le_bytes(), &lane.to_le_bytes()],
                    &mut bytes,
                );
                memory[(lane as usize) * lane_length + column as usize] =
                    Argon2Block::from_bytes(&bytes);
            }
        }
    }

    fn fill_memory(&self, memory: &mut [Argon2Block]) {
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
                                finished: &finished,
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
        let mut addresses = Argon2Block::ZERO;
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
            let block = Argon2Block::compress(view.block(previous), view.block(reference));
            let destination = view.block_mut(current);
            if pass == 0 {
                *destination = block;
            } else {
                *destination ^= block;
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
        addresses: &mut Argon2Block,
        input: &mut Argon2Block,
        start: usize,
        index: usize,
    ) -> u64 {
        if index == start || index.is_multiple_of(Argon2Block::WORDS) {
            input[6] += 1;
            let first = Argon2Block::compress(&Argon2Block::ZERO, input);
            *addresses = Argon2Block::compress(&Argon2Block::ZERO, &first);
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
        let mut c = memory[lane_length - 1];
        for lane in 1..lanes {
            c ^= memory[lane * lane_length + lane_length - 1];
        }
        let bytes = c.to_bytes();
        Self::hash_variable(&[&bytes], output);
    }

    fn hash_variable(inputs: &[&[u8]], output: &mut [u8]) {
        if output.len() <= 64 {
            Self::hash_prefixed(inputs, output.len(), output);
            return;
        }
        let mut v = [0u8; 64];
        Self::hash_prefixed(inputs, output.len(), &mut v);
        let halves = (output.len() - 33) / 32;
        let (head, tail) = output.split_at_mut(32 * halves);
        for (i, chunk) in head.chunks_mut(32).enumerate() {
            if i > 0 {
                v = Blake2b512::digest(&v);
            }
            chunk.copy_from_slice(&v[..32]);
        }
        let mut hasher = Blake2bVar::new(None, tail.len()).expect("H' digest length is 1 to 64");
        hasher.update(&v);
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
}

struct Argon2Segment<'a> {
    segment_length: usize,
    segment_index: usize,
    current: &'a mut [Argon2Block],
    finished: &'a [Option<&'a [Argon2Block]>],
}

impl Argon2Segment<'_> {
    fn block(&self, index: usize) -> &Argon2Block {
        let segment = index / self.segment_length;
        let offset = index % self.segment_length;
        if segment == self.segment_index {
            &self.current[offset]
        } else {
            let segment =
                self.finished[segment].expect("in-progress segments are never referenced");
            &segment[offset]
        }
    }

    fn block_mut(&mut self, index: usize) -> &mut Argon2Block {
        &mut self.current[index % self.segment_length]
    }
}

#[derive(Clone, Copy)]
struct Argon2Block([u64; Self::WORDS]);

impl Argon2Block {
    const WORDS: usize = 128;
    const SIZE: usize = Self::WORDS * 8;
    const MASK: u64 = (1 << 32) - 1;
    const ZERO: Self = Self([0; Self::WORDS]);

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

    fn compress(x: &Self, y: &Self) -> Self {
        let mut r = *x;
        r ^= *y;
        let mut q = r;
        let (chunks, _) = q.0.as_chunks_mut::<16>();
        for chunk in chunks {
            Self::permute(chunk);
        }
        let mut v = [0u64; 16];
        for column in 0..8 {
            for k in 0..8 {
                v[2 * k] = q[16 * k + 2 * column];
                v[2 * k + 1] = q[16 * k + 2 * column + 1];
            }
            Self::permute(&mut v);
            for k in 0..8 {
                q[16 * k + 2 * column] = v[2 * k];
                q[16 * k + 2 * column + 1] = v[2 * k + 1];
            }
        }
        q ^= r;
        q
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

impl BitXorAssign for Argon2Block {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0) {
            *a ^= b;
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex};

    // https://datatracker.ietf.org/doc/html/rfc9106#section-5

    #[test]
    fn test_argon2d() {
        let params = Argon2Params::new(Argon2Variant::Argon2d).memory(32);
        let password = [1u8; 32];
        let salt = [2u8; 16];
        let secret = [3u8; 8];
        let associated_data = [4u8; 12];
        let mut output = [0u8; 32];
        let success = argon2(
            params,
            &password,
            &salt,
            Some(&secret),
            Some(&associated_data),
            &mut output,
        );
        assert!(success);
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
        let mut output = [0u8; 32];
        let success = argon2(
            params,
            &password,
            &salt,
            Some(&secret),
            Some(&associated_data),
            &mut output,
        );
        assert!(success);
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
        let mut output = [0u8; 32];
        let success = argon2(
            params,
            &password,
            &salt,
            Some(&secret),
            Some(&associated_data),
            &mut output,
        );
        assert!(success);
        assert_eq!(
            output,
            hex!("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }
}
