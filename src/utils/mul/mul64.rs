#[allow(clippy::inline_always)]
#[inline(always)]
pub fn unsigned_mul(x: u64, y: u64) -> u128 {
    u128::from(x) * u128::from(y)
}
