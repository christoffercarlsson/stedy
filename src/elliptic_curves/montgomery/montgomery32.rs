use super::{
    Choice, Montgomery, MontgomeryFormParams, PhantomData, WORD_BYTES, WideWord, Word, unsigned_mul,
};

impl_montgomery!(8, 4, 32);
impl_montgomery_wide!(8, 4, 32);
impl_montgomery!(12, 6, 48);
impl_montgomery!(14, 7, 56);
impl_montgomery_wide!(14, 7, 56);
impl_montgomery!(18, 9, 66);
