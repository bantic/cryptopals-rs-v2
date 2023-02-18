use std::collections::HashSet;

use anyhow::Result;
use openssl::symm::{decrypt, Cipher};

pub fn decrypt_aes_ecb(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_128_ecb();
    decrypt(cipher, key, None, bytes).map_err(anyhow::Error::from)
}

pub fn detect_aes_128_ecb(bytes: &[u8]) -> bool {
    let keysize = 16; // always 128-bit/16-byte key
    if bytes.len() % keysize != 0 {
        panic!(
            "Expected aes ciphertext to be a multiple of {} but was {}",
            keysize,
            bytes.len()
        );
    }
    let mut set = HashSet::new();
    for chunk in bytes.chunks_exact(keysize) {
        if set.contains(chunk) {
            return true;
        }
        set.insert(chunk);
    }
    false
}
