#[derive(Clone)]
pub struct Block<const BLOCK_SIZE: usize> {
    buffer: [u8; BLOCK_SIZE],
    buffer_size: u32,
}

impl<const BLOCK_SIZE: usize> Block<BLOCK_SIZE> {
    pub fn new() -> Self {
        Self {
            buffer: [0u8; BLOCK_SIZE],
            buffer_size: 0,
        }
    }

    pub fn blocks<'a>(
        &mut self,
        data: &'a [u8],
    ) -> Option<([u8; BLOCK_SIZE], BlockIterator<'a, BLOCK_SIZE>)> {
        let data_size = data.len();
        let begin = data_size.min(BLOCK_SIZE - self.buffer_size as usize);
        let end = data_size - (data_size - begin) % BLOCK_SIZE;
        self.buffer_chunk(&data[..begin]);
        if (self.buffer_size as usize) < BLOCK_SIZE {
            return None;
        }
        let head = self.buffer;
        let tail = BlockIterator::<BLOCK_SIZE> {
            tail: data,
            begin,
            end,
        };
        self.buffer_size = 0;
        self.buffer_chunk(&data[end..]);
        Some((head, tail))
    }

    pub fn remaining(&self) -> &[u8] {
        &self.buffer[..self.buffer_size as usize]
    }

    pub fn remaining_block(&self) -> Option<([u8; BLOCK_SIZE], usize)> {
        let remaining = self.remaining();
        if remaining.is_empty() {
            return None;
        }
        let size = remaining.len();
        let mut block = [0u8; BLOCK_SIZE];
        block[..size].copy_from_slice(remaining);
        Some((block, size))
    }

    fn buffer_chunk(&mut self, chunk: &[u8]) {
        let buffer_size = self.buffer_size as usize;
        self.buffer[buffer_size..buffer_size + chunk.len()].copy_from_slice(chunk);
        self.buffer_size += chunk.len() as u32;
    }
}

pub struct BlockIterator<'a, const BLOCK_SIZE: usize> {
    tail: &'a [u8],
    begin: usize,
    end: usize,
}

impl<'a, const BLOCK_SIZE: usize> Iterator for BlockIterator<'a, BLOCK_SIZE> {
    type Item = &'a [u8; BLOCK_SIZE];

    fn next(&mut self) -> Option<Self::Item> {
        let begin = self.begin;
        let end = begin + BLOCK_SIZE;
        if end <= self.end {
            self.begin = end;
            let slice = <&[u8; BLOCK_SIZE]>::try_from(&self.tail[begin..end])
                .expect("Each block is BLOCK_SIZE bytes");
            Some(slice)
        } else {
            None
        }
    }
}
