pub trait Xor {
    fn xor(&self, other: &[u8]) -> Vec<u8>;
}

impl Xor for &[u8] {
    fn xor(&self, other: &[u8]) -> Vec<u8> {
        fixed_xor(self, other)
    }
}

impl Xor for Vec<u8> {
    fn xor(&self, other: &[u8]) -> Vec<u8> {
        fixed_xor(self, other)
    }
}

fn fixed_xor(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    if lhs.len() != rhs.len() {
        panic!("Unexpected fixed_xor different-length inputs");
    }

    lhs.iter().zip(rhs).map(|(lhs, rhs)| lhs ^ rhs).collect()
}
