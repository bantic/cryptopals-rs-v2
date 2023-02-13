use std::collections::HashMap;

use crate::frequency::score;

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

pub fn break_single_key(cipher: &[u8]) -> String {
    let len = cipher.len();
    let mut scores = HashMap::<Vec<u8>, (u8, f32)>::new();
    for key in 0..=255 {
        let key = vec![key; len];
        let decoded = cipher.xor(&key);
        let score = score(&decoded);
        scores.insert(decoded, (key[0], score));
    }

    let mut best_score = f32::MAX;
    let mut best = vec![];
    scores.iter().for_each(|(bytes, (_key, score))| {
        if *score < best_score {
            best_score = *score;
            best = bytes.to_vec();
        }
    });

    String::from_utf8_lossy(&best).into()
}
