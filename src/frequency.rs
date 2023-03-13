use itertools::Itertools;
use lazy_static::lazy_static;
use std::collections::{HashMap, HashSet};

#[derive(PartialEq, Eq, Hash)]
enum FreqChar {
    AsciiChar(char),
    AsciiWhitespace,
    AsciiMisc,
    NonAscii,
}

impl From<char> for FreqChar {
    fn from(ch: char) -> FreqChar {
        if !ch.is_ascii() {
            FreqChar::NonAscii
        } else if ch.is_ascii_alphabetic() {
            FreqChar::AsciiChar(ch)
        } else {
            match ch {
                ' ' | '\t' => FreqChar::AsciiWhitespace,
                _ => FreqChar::AsciiMisc,
            }
        }
    }
}

lazy_static! {
    // https://en.wikipedia.org/wiki/Letter_frequency
    static ref CHAR_FREQUENCY: HashMap<FreqChar, f32> = {
        let mut m = HashMap::new();
        m.insert('a'.into(), 0.0609);
        m.insert('b'.into(), 0.0105);
        m.insert('c'.into(), 0.0284);
        m.insert('d'.into(), 0.0292);
        m.insert('e'.into(), 0.1136);
        m.insert('f'.into(), 0.0179);
        m.insert('g'.into(), 0.0138);
        m.insert('h'.into(), 0.0341);
        m.insert('i'.into(), 0.0544);
        m.insert('j'.into(), 0.0024);
        m.insert('k'.into(), 0.0041);
        m.insert('l'.into(), 0.0292);
        m.insert('m'.into(), 0.0276);
        m.insert('n'.into(), 0.0544);
        m.insert('o'.into(), 0.06);
        m.insert('p'.into(), 0.0195);
        m.insert('q'.into(), 0.0024);
        m.insert('r'.into(), 0.0495);
        m.insert('s'.into(), 0.0568);
        m.insert('t'.into(), 0.0803);
        m.insert('u'.into(), 0.0243);
        m.insert('v'.into(), 0.0097);
        m.insert('w'.into(), 0.0138);
        m.insert('x'.into(), 0.0024);
        m.insert('y'.into(), 0.013);
        m.insert('z'.into(), 0.0003);
        m.insert(FreqChar::AsciiMisc, 0.0657);
        m.insert(FreqChar::AsciiWhitespace, 0.1217);
        m.insert(FreqChar::NonAscii, 0.0);
        m
    };
}

lazy_static! {
    /// Ascii bytes in order for frequency.
    /// Todo: Include capitalized letters too
    pub static ref BYTES_BY_FREQ: Vec<u8> = {
        let mut seen = HashSet::new();
        let mut bytes = vec![];
        for (fc, _pct) in CHAR_FREQUENCY
            .iter()
            .sorted_by_key(|&(_fc, pct)| (10000.0 * pct) as u32)
            .rev()
        {
            if let FreqChar::AsciiChar(ch) = fc {
                bytes.push(*ch as u8);
                seen.insert(*ch as u8);
            }
        }
        for byte in u8::MIN..=u8::MAX {
            if !seen.contains(&byte) {
                bytes.push(byte);
                seen.insert(byte);
            }
        }
        bytes
    };
}

fn counts(s: &[char]) -> HashMap<FreqChar, usize> {
    let mut counts = HashMap::<FreqChar, usize>::new();
    s.iter().for_each(|&ch| {
        counts
            .entry(ch.into())
            .and_modify(|counter| *counter += 1)
            .or_insert(1);
    });
    counts
}

pub fn score(bytes: &[u8]) -> u32 {
    let l = bytes.len();
    let mut score = 0.0;
    if !bytes.is_ascii() {
        // TODO: we shouldn't disregard non-ascii output, this could
        // drop actual messages (like ones w emoji in them)
        return u32::MAX;
    }
    if bytes
        .iter()
        .any(|&b| (b as char) != '\n' && b.to_ascii_lowercase().is_ascii_control())
    {
        return u32::MAX;
    }
    let bytes: Vec<char> = bytes
        .iter()
        .flat_map(|&b| (b as char).to_lowercase())
        .collect();
    counts(&bytes).iter().for_each(|(char, &count)| {
        let expected = CHAR_FREQUENCY.get(char).unwrap_or(&0.0);
        let actual = count as f32 / l as f32;
        score += (expected - actual).powi(2);
    });

    (1000.0 * score) as u32
}
