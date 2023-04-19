use anyhow::bail;
use rand::Rng;
use std::{thread, time};

// https://en.wikipedia.org/wiki/Mersenne_Twister
const W: u32 = 32;
const N: u32 = 624;
const F: u32 = 1812433253;
const M: u32 = 397;
const A: u32 = 0x9908B0DF;
const D: u32 = 0xFFFFFFFF;
const B: u32 = 0x9D2C5680;
const C: u32 = 0xEFC60000;
const U: u8 = 11;
const S: u8 = 7;
const T: u8 = 15;
const L: u8 = 18;
const LOWER_MASK: u32 = 0b0111_1111_1111_1111_1111_1111_1111_1111;
const UPPER_MASK: u32 = 0b1000_0000_0000_0000_0000_0000_0000_0000;

pub struct Mt19937 {
    pub seed: u32,
    count: u32,
    mt: Vec<u32>,
}

// Reference: https://github.com/anneouyang/MT19937/blob/master/code/implement_mt19937.py
// and https://en.wikipedia.org/wiki/Mersenne_Twister#Algorithmic_detail
impl Mt19937 {
    pub fn new(seed: Option<u32>) -> Self {
        let seed = match seed {
            Some(s) => s,
            None => crate::utils::time::now().as_secs() as u32,
        };
        let mut out = Mt19937 {
            seed,
            count: 0,
            mt: vec![0; N as usize],
        };
        out.init();
        out
    }

    fn init(&mut self) {
        self.mt[0] = self.seed;
        for i in 1..N {
            let prev_x = self.mt[(i - 1) as usize];
            let x = F.wrapping_mul(prev_x ^ (prev_x >> (W - 2))).wrapping_add(i);
            self.mt[i as usize] = x;
        }
        self.twist();
    }

    fn twist(&mut self) {
        for i in 0..N {
            let idx = i as usize;
            let next_idx = ((i + 1) % N) as usize;
            let x = (self.mt[idx] & UPPER_MASK) | (self.mt[next_idx] & LOWER_MASK);
            let mut x_a = x >> 1;
            if (x % 2) != 0 {
                x_a ^= A;
            }
            let twist_idx = ((i + M) % N) as usize;
            self.mt[idx] = self.mt[twist_idx] ^ x_a;
        }
        self.count = 0;
    }

    pub fn temper(&mut self) -> u32 {
        if self.count == N {
            self.twist();
        }
        let y = self.mt[self.count as usize];
        let y = y ^ ((y >> U) & D);
        let y = y ^ ((y << S) & B);
        let y = y ^ ((y << T) & C);
        let y = y ^ (y >> L);
        self.count += 1;
        y
    }
}

pub fn random_mt19937() -> anyhow::Result<Mt19937> {
    let mut rng = rand::thread_rng();

    let duration = time::Duration::from_millis(rng.gen_range(0..=100));
    thread::sleep(duration);

    let seed = time::SystemTime::now()
        .duration_since(time::SystemTime::UNIX_EPOCH)?
        .as_millis()
        / 1_000; // TODO -- if we don't reduce the seed, we end up getting a
                 // panic in the temper function.
                 // Something incorrect w/ the temper function.

    let duration = time::Duration::from_millis(rng.gen_range(0..=100));
    thread::sleep(duration);

    Ok(Mt19937::new(Some(seed as u32)))
}

pub fn crack_random_mt19937(rnd: &mut Mt19937) -> anyhow::Result<u32> {
    let seed = time::SystemTime::now()
        .duration_since(time::SystemTime::UNIX_EPOCH)?
        .as_millis()
        / 1_000; // See the TODO in random_mt19937

    let sequence: Vec<u32> = (0..=10).map(|_| rnd.temper()).collect();

    for delta in 0..=200 {
        for dir in [-1i8, 1i8] {
            let possible_seed = match dir {
                -1 => seed - delta,
                1 => seed + delta,
                _ => bail!("bad dir"),
            } as u32;
            let mut possible_rnd = Mt19937::new(Some(possible_seed));
            let possible_sequence: Vec<u32> = (0..=10).map(|_| possible_rnd.temper()).collect();

            if compare_seqs(&sequence, &possible_sequence) {
                return Ok(possible_seed);
            }
        }
    }

    bail!("Could not crack seed");
}

// checks if any ending sub-slice of rhs equals the start of lhs
fn compare_seqs(lhs: &[u32], rhs: &[u32]) -> bool {
    //   1 2 [ 3 4   5 6 ]
    // [ 1 2   3 4 ] 5 6
    if lhs == rhs {
        return true;
    }
    for size in 1..rhs.len() {
        dbg!((size, lhs, &rhs[size..]));
        if lhs.starts_with(&rhs[size..]) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::mersenne::compare_seqs;

    #[test]
    fn test_compare_seqs() {
        assert!(compare_seqs(&[1, 2, 3, 4], &[1, 2, 3, 4]));
        assert!(compare_seqs(&[1, 2, 3, 4], &[15, 14, 1, 2]));
        assert!(compare_seqs(&[1, 2, 3], &[14, 1, 2]));
        assert!(!compare_seqs(&[3, 3, 4], &[14, 1, 2]));
    }
}
