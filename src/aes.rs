use std::collections::{HashMap, HashSet};

use anyhow::{bail, ensure, Result};
use openssl::symm::{decrypt, encrypt, Cipher};

#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    ECB,
    CBC,
}

use crate::{
    oracle::encrypt_ecb_with_consistent_key,
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

pub fn break_ecb() -> anyhow::Result<Vec<u8>> {
    fn detect_block_size() -> anyhow::Result<usize> {
        for len in 2..=255 {
            let plaintext = vec![b'A'; len * 2];
            let encrypted = encrypt_ecb_with_consistent_key(&plaintext)?;
            let mut chunks = encrypted.chunks_exact(len);
            let a = chunks.next().unwrap();
            let b = chunks.next().unwrap();
            if a == b {
                return Ok(len);
            }
        }
        bail!("Could not detect block size");
    }
    fn ensure_ecb(blocksize: usize) -> anyhow::Result<()> {
        let plaintext = vec![b'A'; blocksize * 3];
        let encrypted = encrypt_ecb_with_consistent_key(&plaintext)?;
        ensure!(detect_aes_128_ecb(&encrypted), "expected to confirm ecb");
        Ok(())
    }
    let blocksize = detect_block_size()?;
    ensure_ecb(blocksize)?;

    fn detect_payload_length(blocksize: usize) -> anyhow::Result<usize> {
        // The payload is pkcs7 padded, so the encrypt length will always be a multiple
        // of the blocksize.
        // Keep adding a byte at a time to the plaintext len until the ciphertext
        // jumps by blocksize -- that was the number of padding bytes added to the original plaintext
        let curlen = encrypt_ecb_with_consistent_key(&[])?.len();
        for padlen in 1..blocksize {
            let pad = vec![b'A'; padlen];
            let len = encrypt_ecb_with_consistent_key(&pad)?.len();
            if len != curlen {
                ensure!(len - curlen == blocksize);
                return Ok(curlen - padlen);
            }
        }
        bail!("Did not find a length");
    }

    fn map_decrypt_bytes(prefix: &[u8], blocksize: usize) -> anyhow::Result<HashMap<Vec<u8>, u8>> {
        let mut map = HashMap::new();
        let mut input = prefix.to_vec();
        for input_byte in 0u8..=255 {
            input.truncate(blocksize - 1);
            input.push(input_byte);
            ensure!(input.len() == blocksize);
            let mut encrypted = encrypt_ecb_with_consistent_key(&input)?;
            encrypted.truncate(blocksize);
            map.insert(encrypted, input_byte);
        }
        Ok(map)
    }

    fn decrypt_byte_idx(idx: usize, blocksize: usize, decrypted: &[u8]) -> anyhow::Result<u8> {
        // add prefix padding to align idx with the end of a known block
        ensure!(
            idx <= decrypted.len(),
            "cannot decrypt a byte at idx that we haven't seen yet {}:{}",
            idx,
            decrypted.len()
        );
        let padlen = blocksize - (idx % blocksize) - 1;
        let pad = vec![b'A'; padlen]; // will align the result so that idx is at the end of a block

        let known_prefix = if idx < blocksize {
            let mut known = pad.to_vec();
            known.extend(&decrypted[0..idx]);
            known
        } else {
            decrypted[(idx + 1 - blocksize)..idx].to_vec()
        };
        ensure!(
            known_prefix.len() == blocksize - 1,
            "expected known prefix of len {}, got {}: {:?}",
            blocksize - 1,
            known_prefix.len(),
            known_prefix
        );

        let map = map_decrypt_bytes(&known_prefix, blocksize)?;
        let encrypted = encrypt_ecb_with_consistent_key(&pad)?;
        let target_block_start = if idx < blocksize {
            0
        } else {
            pad.len() + idx + 1 - blocksize
        };
        let target_block = encrypted[target_block_start..(target_block_start + blocksize)].to_vec();
        ensure!(target_block.len() == blocksize);

        let found = map.get(&target_block);
        ensure!(found.is_some(), "expected to get something from target");
        Ok(*found.unwrap())
    }

    let encrypt_len = detect_payload_length(blocksize)?;

    let mut decrypted = vec![];
    for byte_idx in 0..encrypt_len {
        let byte = decrypt_byte_idx(byte_idx, blocksize, &decrypted)?;
        decrypted.push(byte);
    }

    Ok(decrypted)
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
