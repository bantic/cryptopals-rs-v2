use lazy_static::lazy_static;
use rand::Rng;

use crate::{aes, base64, utils::bytes};

lazy_static! {
    static ref CONSISTENT_KEY: Vec<u8> = bytes::rand_of_len(16);
}
const CHALLENGE12_INPUT: &str = include_str!("./files/12.txt");

pub struct Oracle {
    pub ciphertext: Vec<u8>,
    mode: aes::Mode,
}

impl Oracle {
    pub fn verify(&self, mode: &aes::Mode) -> bool {
        &self.mode == mode
    }
}

pub fn guess(oracle: &Oracle) -> aes::Mode {
    match aes::detect_aes_128_ecb(&oracle.ciphertext) {
        true => aes::Mode::ECB,
        false => aes::Mode::CBC,
    }
}

pub fn encrypt(plaintext: &[u8]) -> anyhow::Result<Oracle> {
    let block_size = 16;
    let key = &bytes::rand_of_len(block_size);
    let mut data = vec![];

    let mut rng = rand::thread_rng();
    let prepend_len = rng.gen_range(5..=15);
    let append_len = rng.gen_range(5..=15);
    data.extend(bytes::rand_of_len(prepend_len));
    data.extend(plaintext);
    data.extend(bytes::rand_of_len(append_len));

    let mode;
    let ciphertext = if rand::random() {
        mode = aes::Mode::ECB;
        aes::encrypt_aes_ecb(&data, key)?
    } else {
        mode = aes::Mode::CBC;
        let iv = bytes::rand_of_len(block_size);
        aes::encrypt_aes_cbc(&data, &iv, key)?
    };
    Ok(Oracle { ciphertext, mode })
}

pub fn encrypt_ecb_with_consistent_key(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut plaintext = plaintext.to_vec();
    let unknown = base64::from_file_str(CHALLENGE12_INPUT);
    plaintext.extend(&unknown);
    aes::encrypt_aes_ecb(&plaintext, &CONSISTENT_KEY)
}
