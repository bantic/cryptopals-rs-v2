pub trait HammingDistance {
    fn hamming_distance(&self, _: &Self) -> u32;
}

impl HammingDistance for &str {
    fn hamming_distance(&self, other: &Self) -> u32 {
        if self.len() != other.len() {
            panic!("HammingDistance must have equal lengths");
        }
        self.as_bytes().hamming_distance(&other.as_bytes())
    }
}

impl HammingDistance for &[u8] {
    fn hamming_distance(&self, other: &Self) -> u32 {
        if self.len() != other.len() {
            panic!("HammingDistance must have equal lengths");
        }
        self.iter()
            .zip(other.iter())
            .map(|(lhs, rhs)| (lhs ^ rhs).count_ones())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use crate::hamming::HammingDistance;

    #[test]
    fn test_hamming_distance() {
        let lhs = "this is a test";
        let rhs = "wokka wokka!!!";
        assert_eq!(lhs.hamming_distance(&rhs), 37);
    }
}
