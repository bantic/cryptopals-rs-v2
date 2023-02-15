use std::{cmp::min, iter::zip};

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

fn single_key_options(cipher: &[u8]) -> impl Iterator<Item = (u32, u8, Vec<u8>)> + '_ {
    (u8::MIN..=u8::MAX)
        .map(|key| {
            let decoded = cipher.xor(&[key]);
            let score = score(&decoded);
            (score, key, decoded)
        })
        .sorted_by_key(|x| x.0)
}

pub fn break_single_key(cipher: &[u8]) -> String {
    for (_score, _key, decoded) in single_key_options(cipher) {
        // Return the first valid utf8 string from the options
        if let Ok(out) = String::from_utf8(decoded) {
            return out;
        }
    }
    panic!("Could not find suitable utf8 decoded");
}

pub fn break_single_key_multilines(input: &str) -> String {
    match input
        .lines()
        .map(|l| l.trim())
        .filter_map(|line| single_key_options(&line.to_hex_bytes()).next())
        .sorted_by_key(|x| x.0)
        .next()
    {
        Some((_score, _key, decoded)) => String::from_utf8_lossy(&decoded).into(),
        None => panic!("Could not fine suitable line in break multiline"),
    }
}

pub fn find_repeating_xor_keysize(bytes: &[u8]) -> impl Iterator<Item = (usize, u32)> {
    let chunk_count = 4;
    let min_keysize = 2;
    if bytes.len() < chunk_count * min_keysize {
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
            let normalized_dist = 1000.0 * sum as f32 / keysize as f32;
            (keysize, normalized_dist as u32)
        })
        .sorted_by_key(|(_keysize, dist)| *dist)
}
