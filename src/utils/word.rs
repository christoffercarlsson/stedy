pub trait Word: Copy {
    fn add(self, other: Self) -> Self;

    fn xor(self, other: Self) -> Self;

    fn rotate(self, bits: u32) -> Self;
}

impl Word for u32 {
    fn add(self, other: Self) -> Self {
        self.wrapping_add(other)
    }

    fn xor(self, other: Self) -> Self {
        self ^ other
    }

    fn rotate(self, bits: u32) -> Self {
        self.rotate_left(bits)
    }
}

impl<const N: usize> Word for [u32; N] {
    fn add(self, other: Self) -> Self {
        core::array::from_fn(|i| self[i].wrapping_add(other[i]))
    }

    fn xor(self, other: Self) -> Self {
        core::array::from_fn(|i| self[i] ^ other[i])
    }

    fn rotate(self, bits: u32) -> Self {
        self.map(|word| word.rotate_left(bits))
    }
}
