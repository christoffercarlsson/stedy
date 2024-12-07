pub fn xor(a: &[u8], b: &[u8], c: &mut [u8]) {
    for ((&x, &y), z) in a.iter().zip(b).zip(c) {
        *z = x ^ y;
    }
}
