#[allow(clippy::inline_always)]
#[inline(always)]
pub fn unsigned_mul(x: u32, y: u32) -> u64 {
    u64::from(x) * u64::from(y)
}

#[allow(clippy::inline_always)]
#[inline(always)]
pub fn signed_mul(x: i32, y: i32) -> i64 {
    i64::from(x) * i64::from(y)
}
