use crate::utils::Choice;

pub fn is_zero(a: &[u8]) -> Choice {
    !Choice::nonzero(a.iter().fold(0, |acc, &x| acc | x))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_zero() {
        assert!(is_zero(&[0; 16]).to_bool());
        assert!(is_zero(&[]).to_bool());
        assert!(!is_zero(&[1; 16]).to_bool());
        assert!(!is_zero(&[0, 0, 0, 1]).to_bool());
        assert!(!is_zero(&[1, 0, 0, 0]).to_bool());
    }
}
