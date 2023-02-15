use std::{cmp::min, collections::HashMap, iter::zip};

use itertools::Itertools;

use crate::{frequency::score, hamming::HammingDistance, hex::ToHexBytes};

pub trait Xor {
    fn xor(&self, other: &[u8]) -> Vec<u8>;
}

impl Xor for [u8] {
    fn xor(&self, other: &[u8]) -> Vec<u8> {
        xor(self, other)
    }
}

fn xor(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    zip(lhs, rhs.iter().cycle()).map(|(l, r)| l ^ r).collect()
}

fn single_key_options(cipher: &[u8]) -> HashMap<u8, f32> {
    let mut scores = HashMap::<u8, f32>::new();
    for key in 0..=255 {
        let decoded = cipher.xor(&[key]);
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
    String::from_utf8_lossy(&cipher.xor(&[best_key])).into()
}

pub fn break_single_key_multilines(input: &str) -> String {
    let mut best_score = f32::MAX;
    let mut best_bytes = vec![];

    for line in input.lines() {
        let cipher = line.trim().to_hex_bytes();
        let (cur_best_key, cur_best_score) = best_single_key(&cipher);
        if cur_best_score < best_score {
            best_score = cur_best_score;
            best_bytes = cipher.xor(&[cur_best_key]);
        }
    }

    String::from_utf8_lossy(&best_bytes).into()
}

// fn find_repeating_xor_keysize(bytes: &[u8]) -> std::iter::Rev<std::vec::IntoIter<(usize, u32)>> {
fn find_repeating_xor_keysize(bytes: &[u8]) -> impl Iterator<Item = (usize, u32)> {
    let chunk_count = 4;
    let min_keysize = 2;
    if bytes.len() > chunk_count * min_keysize {
        panic!(
            "Cannot find keysize when bytes is too short: {}",
            bytes.len()
        );
    }
    let max_keysize = min(40, bytes.len() / chunk_count);

    (min_keysize..=max_keysize)
        .map(|keysize| {
            let chunks = bytes.chunks(keysize).take(chunk_count);
            let x = chunks.combinations(2);
            let sum: u32 = x
                .map(|x| {
                    let lhs = x.get(0).unwrap();
                    let rhs = x.get(1).unwrap();
                    lhs.hamming_distance(rhs)
                })
                .sum();
            let normalized_dist = 100.0 * sum as f32 / keysize as f32;
            (keysize, normalized_dist as u32)
        })
        .sorted_by_key(|(_keysize, dist)| *dist)
        .rev()
}
