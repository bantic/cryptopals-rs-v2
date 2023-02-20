use std::collections::HashSet;

use anyhow::{ensure, Result};
use openssl::symm::{decrypt, encrypt, Cipher};

#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    ECB,
    CBC,
}

use crate::{
    padding::{PadPkcs7, UnpadPkcs7},
    xor::Xor,
};

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

pub fn encrypt_aes_ecb(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_128_ecb();
    encrypt(cipher, key, None, bytes).map_err(anyhow::Error::from)
}

pub fn encrypt_aes_cbc(bytes: &[u8], iv: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let block_size = 16;
    let bytes = bytes.pad_pkcs7();
    let mut iv = iv.to_vec();
    let mut encrypted = vec![];
    for block in bytes.chunks_exact(block_size) {
        let encrypted_block = encrypt_aes_ecb_block(&block.xor(&iv), key)?;
        encrypted.extend(&encrypted_block);
        iv = encrypted_block;
    }

    Ok(encrypted)
}

pub fn decrypt_aes_cbc(bytes: &[u8], iv: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let block_size = 16;
    ensure!(
        bytes.len() % block_size == 0,
        "expected multiple of {block_size} expected, got {}",
        bytes.len()
    );
    let mut iv = iv;
    let mut decrypted = vec![];
    for block in bytes.chunks_exact(block_size) {
        let decrypted_block = decrypt_aes_cbc_block(block, iv, key)?;
        decrypted.extend(decrypted_block);
        iv = block;
    }

    Ok(decrypted.unpad_pkcs7())
}

fn encrypt_aes_ecb_block(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let block_size = 16;
    ensure!(
        bytes.len() == block_size,
        "expected len of {}, got {}",
        block_size,
        bytes.len()
    );
    let mut encrypted = encrypt_aes_ecb(bytes, key)?;
    encrypted.truncate(block_size);
    Ok(encrypted)
}

fn decrypt_aes_cbc_block(bytes: &[u8], iv: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        bytes.len() == 16,
        "block size of 16 expected, got {}",
        bytes.len()
    );
    let padding = &(vec![]).pad_pkcs7();
    let encrypted_padding = encrypt_aes_ecb_block(padding, key)?;
    let mut bytes = bytes.to_vec();
    bytes.extend(encrypted_padding);
    Ok(decrypt_aes_ecb(&bytes, key)?.xor(iv))
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use crate::{
        aes::{decrypt_aes_cbc, decrypt_aes_ecb, encrypt_aes_cbc, encrypt_aes_ecb},
        utils::bytes,
    };

    #[test]
    fn test_encrypt_decrypt_aes_128_ecb() {
        for _ in 0..10 {
            let bytes = bytes::rand_of_len(16);
            let key = bytes::rand_of_len(16);
            let encrypted = encrypt_aes_ecb(&bytes, &key).unwrap();
            assert_eq!(decrypt_aes_ecb(&encrypted, &key).unwrap(), bytes);
        }
    }

    #[test]
    fn test_encrypt_decrypt_aes_128_cbc() {
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let len = rng.gen_range(10..=50);
            let bytes = bytes::rand_of_len(len);
            let key = bytes::rand_of_len(16);
            let iv = bytes::rand_of_len(16);
            let encrypted = encrypt_aes_cbc(&bytes, &iv, &key).unwrap();
            assert_eq!(decrypt_aes_cbc(&encrypted, &iv, &key).unwrap(), bytes);
        }
    }
}
