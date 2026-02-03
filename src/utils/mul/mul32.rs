#[inline(always)]
pub fn unsigned_mul(x: u32, y: u32) -> u64 {
    (x as u64) * (y as u64)
}

#[inline(always)]
pub fn signed_mul(x: i32, y: i32) -> i64 {
    (x as i64) * (y as i64)
}
