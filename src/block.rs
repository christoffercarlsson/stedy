#[derive(Copy, Clone)]
pub struct Block<const BLOCK_SIZE: usize> {
    buffer: [u8; BLOCK_SIZE],
    buffer_size: usize,
}

impl<const BLOCK_SIZE: usize> Block<BLOCK_SIZE> {
    pub fn new() -> Self {
        Self {
            buffer: [0u8; BLOCK_SIZE],
            buffer_size: 0,
        }
    }

    pub fn blocks(&mut self, data: &[u8]) -> (Option<[u8; BLOCK_SIZE]>, BlockIterator<BLOCK_SIZE>) {
        let begin = data.len().min(BLOCK_SIZE - self.buffer_size);
        self.buffer_chunk(&data[..begin]);
        let buffer = if self.buffer_size == BLOCK_SIZE {
            self.buffer_size = 0;
            Some(self.buffer)
        } else {
            None
        };
        let end = data.len() - (data.len() - begin) % BLOCK_SIZE;
        self.buffer_chunk(&data[end..]);
        (buffer, BlockIterator::<BLOCK_SIZE> { begin, end })
    }

    fn buffer_chunk(&mut self, chunk: &[u8]) {
        self.buffer[self.buffer_size..self.buffer_size + chunk.len()].copy_from_slice(chunk);
        self.buffer_size += chunk.len();
    }

    pub fn remaining(&self) -> &[u8] {
        &self.buffer[..self.buffer_size]
    }
}

pub struct BlockIterator<const BLOCK_SIZE: usize> {
    begin: usize,
    end: usize,
}

impl<const BLOCK_SIZE: usize> Iterator for BlockIterator<BLOCK_SIZE> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let begin = self.begin;
        let end = begin + BLOCK_SIZE;
        if end <= self.end {
            self.begin = end;
            Some((begin, end))
        } else {
            None
        }
    }
}
