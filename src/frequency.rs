use lazy_static::lazy_static;
use std::collections::HashMap;

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
        m.insert('a'.into(), 0.082);
        m.insert('b'.into(), 0.015);
        m.insert('c'.into(), 0.028);
        m.insert('d'.into(), 0.043);
        m.insert('e'.into(), 0.13);
        m.insert('f'.into(), 0.022);
        m.insert('g'.into(), 0.020);
        m.insert('h'.into(), 0.061);
        m.insert('i'.into(), 0.07);
        m.insert('j'.into(), 0.015);
        m.insert('k'.into(), 0.077);
        m.insert('l'.into(), 0.040);
        m.insert('m'.into(), 0.024);
        m.insert('n'.into(), 0.067);
        m.insert('o'.into(), 0.075);
        m.insert('p'.into(), 0.019);
        m.insert('q'.into(), 0.0095);
        m.insert('r'.into(), 0.06);
        m.insert('s'.into(), 0.063);
        m.insert('t'.into(), 0.091);
        m.insert('u'.into(), 0.028);
        m.insert('v'.into(), 0.0098);
        m.insert('w'.into(), 0.024);
        m.insert('x'.into(), 0.0015);
        m.insert('y'.into(), 0.02);
        m.insert('z'.into(), 0.00074);
        m.insert(FreqChar::AsciiMisc, 0.005);
        m.insert(FreqChar::AsciiWhitespace, 0.10);
        m.insert(FreqChar::NonAscii, 0.0);
        m
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

pub fn score(bytes: &[u8]) -> f32 {
    let l = bytes.len();
    let mut score = 0.0;
    if !bytes.is_ascii() {
        // TODO: we shouldn't disregard non-ascii output, this could
        // drop actual messages (like ones w emoji in them)
        return f32::MAX;
    }
    if bytes
        .iter()
        .any(|&b| (b as char) != '\n' && b.to_ascii_lowercase().is_ascii_control())
    {
        return f32::MAX;
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

    score
}
