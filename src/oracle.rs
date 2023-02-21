use rand::Rng;

use crate::{aes, utils::bytes};

pub struct Oracle<T> {
    pub ciphertext: Vec<u8>,
    mode: T,
}

impl Oracle<aes::Mode> {
    pub fn verify(&self, mode: &aes::Mode) -> bool {
        &self.mode == mode
    }
}

pub fn guess(oracle: &Oracle<aes::Mode>) -> aes::Mode {
    match aes::detect_aes_128_ecb(&oracle.ciphertext) {
        true => aes::Mode::ECB,
        false => aes::Mode::CBC,
    }
}

pub fn encrypt(plaintext: &[u8]) -> anyhow::Result<Oracle<aes::Mode>> {
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

pub struct PaddingOracle {
    key: Vec<u8>,
    secret: Vec<u8>,
}

impl PaddingOracle {
    pub fn new(secret: Vec<u8>) -> Self {
        let blocksize = 16;
        let key = bytes::rand_of_len(blocksize);
        PaddingOracle { key, secret }
    }
    pub fn encrypt(&self, padding: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut plaintext = vec![];
        plaintext.extend(padding);
        plaintext.extend(&self.secret);
        aes::encrypt_aes_ecb(&plaintext, &self.key)
    }
    pub fn verify(&self, plaintext: &[u8]) -> bool {
        self.secret == plaintext
    }
}
