use std::collections::HashSet;

use anyhow::{bail, ensure, Result};
use openssl::symm::{decrypt, encrypt, Cipher};

#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    ECB,
    CBC,
}

use crate::{
    frequency::BYTES_BY_FREQ,
    oracle::{PaddingOracle, ProfileOracle},
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

pub fn break_ecb(oracle: &PaddingOracle) -> anyhow::Result<Vec<u8>> {
    fn detect_block_size(oracle: &PaddingOracle) -> anyhow::Result<usize> {
        for len in 2..=255 {
            let plaintext = vec![b'A'; len * 2];
            let encrypted = oracle.encrypt(&plaintext)?;
            let mut chunks = encrypted.chunks_exact(len);
            let a = chunks.next().unwrap();
            let b = chunks.next().unwrap();
            if a == b {
                return Ok(len);
            }
        }
        bail!("Could not detect block size");
    }

    fn ensure_ecb(blocksize: usize, oracle: &PaddingOracle) -> anyhow::Result<()> {
        let plaintext = vec![b'A'; blocksize * 3];
        let encrypted = oracle.encrypt(&plaintext)?;
        ensure!(detect_aes_128_ecb(&encrypted), "expected to confirm ecb");
        Ok(())
    }

    fn detect_payload_length(blocksize: usize, oracle: &PaddingOracle) -> anyhow::Result<usize> {
        // The payload is pkcs7 padded, so the encrypt length will always be a multiple
        // of the blocksize.
        // Keep adding a byte at a time to the plaintext len until the ciphertext
        // jumps by blocksize -- that was the number of padding bytes added to the original plaintext
        let curlen = oracle.encrypt(&[])?.len();
        for padlen in 1..blocksize {
            let pad = vec![b'A'; padlen];
            let len = oracle.encrypt(&pad)?.len();
            if len != curlen {
                ensure!(len - curlen == blocksize);
                return Ok(curlen - padlen);
            }
        }
        bail!("Did not find a length");
    }

    fn detect_byte(
        oracle: &PaddingOracle,
        prefix: &[u8],
        blocksize: usize,
        target: &[u8],
    ) -> anyhow::Result<u8> {
        let mut input = prefix.to_vec();
        ensure!(input.len() == blocksize - 1);
        for &probe_byte in BYTES_BY_FREQ.iter() {
            input.truncate(blocksize - 1);
            input.push(probe_byte);
            let mut encrypted = oracle.encrypt(&input)?;
            encrypted.truncate(blocksize);
            if encrypted == target {
                return Ok(probe_byte);
            }
        }
        bail!("Failed to detect byte");
    }

    fn decrypt_byte_idx(
        oracle: &PaddingOracle,
        idx: usize,
        blocksize: usize,
        decrypted: &[u8],
    ) -> anyhow::Result<u8> {
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

        let encrypted = oracle.encrypt(&pad)?;
        let target_block_start = if idx < blocksize {
            0
        } else {
            pad.len() + idx + 1 - blocksize
        };
        let target_block = encrypted[target_block_start..(target_block_start + blocksize)].to_vec();
        ensure!(target_block.len() == blocksize);
        let found_byte = detect_byte(oracle, &known_prefix, blocksize, &target_block)?;
        Ok(found_byte)
    }

    let blocksize = detect_block_size(oracle)?;
    ensure_ecb(blocksize, oracle)?;
    let encrypt_len = detect_payload_length(blocksize, oracle)?;
    let mut decrypted = vec![];
    for byte_idx in 0..encrypt_len {
        let byte = decrypt_byte_idx(oracle, byte_idx, blocksize, &decrypted)?;
        decrypted.push(byte);
    }

    Ok(decrypted)
}

pub fn break_ecb_cut_paste(oracle: &ProfileOracle) -> anyhow::Result<Vec<u8>> {
    // TODO: Make "detect_block_size" generic over oracles
    fn detect_block_size(oracle: &ProfileOracle) -> anyhow::Result<usize> {
        let mut data = vec![b'A'];
        let len = oracle.encrypt(&data)?.len();
        for padlen in 2..=255 {
            data.resize(padlen, b'A');
            let newlen = oracle.encrypt(&data)?.len();
            if newlen != len {
                return Ok(newlen - len);
            }
        }
        bail!("Could not detect block size");
    }

    // TODO: make this generic over oracles
    fn ensure_ecb(blocksize: usize, oracle: &ProfileOracle) -> anyhow::Result<()> {
        let plaintext = vec![b'A'; blocksize * 3];
        let encrypted = oracle.encrypt(&plaintext)?;
        ensure!(detect_aes_128_ecb(&encrypted), "expected to confirm ecb");
        Ok(())
    }

    let blocksize = detect_block_size(oracle)?;
    ensure_ecb(blocksize, oracle)?;

    // TODO detect alignlen assuming we don't know how much prefix padding is added
    let alignlen = blocksize - "email=".len();
    let mut email = vec![b'A'; alignlen];
    email.extend("admin".as_bytes().pad_pkcs7());
    email.extend("@a.com".as_bytes()); // to look like an email
    let encrypted = oracle.encrypt(&email)?;
    let target_start = "email=".len() + alignlen;
    let target_end = target_start + blocksize;
    let target_bytes = &encrypted[target_start..target_end];

    // align email=X&uid=10&role= to end of block
    let mut email_prefix = vec![b'A'];
    let email_suffix = "@a.com";
    while ("email=".len() + email_prefix.len() + email_suffix.len() + "&uid=10&role=".len())
        % blocksize
        != 0
    {
        email_prefix.push(b'A');
    }
    email_prefix.extend(email_suffix.as_bytes()); // make it look like an email
    let email = email_prefix;
    let mut encrypted = oracle.encrypt(&email)?;
    encrypted.truncate(encrypted.len() - blocksize); // drop last block
    encrypted.extend(target_bytes); // add back an "admin" + fake padded block

    Ok(encrypted)
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
