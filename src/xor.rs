use std::collections::HashMap;

use crate::{frequency::score, hex::ToHexBytes};

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

fn single_key_options(cipher: &[u8]) -> HashMap<u8, f32> {
    let len = cipher.len();
    let mut scores = HashMap::<u8, f32>::new();
    for key in 0..=255 {
        let decoded = cipher.xor(&vec![key; len]);
        let score = score(&decoded);
        scores.insert(key, score);
    }
    scores
}

pub fn best_single_key(cipher: &[u8]) -> (u8, f32) {
    let scores = single_key_options(cipher);
    let mut best_score = f32::MAX;
    let mut best_key = 0;
    for (key, score) in scores {
        if score < best_score {
            best_score = score;
            best_key = key;
        }
    }

    (best_key, best_score)
}

pub fn break_single_key(cipher: &[u8]) -> String {
    let (best_key, _best_score) = best_single_key(cipher);
    String::from_utf8_lossy(&cipher.xor(&vec![best_key; cipher.len()])).into()
}

pub fn break_single_key_multilines(input: &str) -> String {
    let mut best_score = f32::MAX;
    let mut best_bytes = vec![];

    for line in input.lines() {
        let cipher = line.trim().to_hex_bytes();
        let (cur_best_key, cur_best_score) = best_single_key(&cipher);
        if cur_best_score < best_score {
            best_score = cur_best_score;
            best_bytes = cipher.xor(&vec![cur_best_key; cipher.len()]);
        }
    }

    String::from_utf8_lossy(&best_bytes).into()
}
