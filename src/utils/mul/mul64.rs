#[inline(always)]
pub fn unsigned_mul(x: u64, y: u64) -> u128 {
    (x as u128) * (y as u128)
}

#[allow(dead_code)]
#[inline(always)]
pub fn signed_mul(x: i64, y: i64) -> i128 {
    (x as i128) * (y as i128)
}
