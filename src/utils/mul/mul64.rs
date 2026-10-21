#[inline(always)]
pub fn unsigned_mul(x: u64, y: u64) -> u128 {
    (x as u128) * (y as u128)
}
