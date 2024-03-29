use std::{collections::HashSet, error::Error, fmt, iter::once};

use anyhow::{bail, ensure, Result};
use itertools::Itertools;
use openssl::symm::{decrypt, encrypt, Cipher};

#[derive(Debug)]
pub enum AesError {
    InvalidPadding(String),
}

impl Error for AesError {}

impl fmt::Display for AesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    ECB,
    CBC,
    CTR,
}

use crate::{
    frequency::BYTES_BY_FREQ,
    oracle::{CbcOracle, CbcPaddingOracle, EncryptingOracle, ProfileOracle},
    padding::{PadPkcs7, UnpadPkcs7},
    utils::bytes,
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

pub fn encrypt_aes_ctr(bytes: &[u8], key: &[u8], nonce: u64) -> Result<Vec<u8>> {
    stream_aes_ctr(bytes, key, nonce)
}

fn stream_aes_ctr(bytes: &[u8], key: &[u8], nonce: u64) -> Result<Vec<u8>> {
    let blocksize = 16;
    let mut out = vec![];
    for (idx, block) in bytes.chunks(blocksize).enumerate() {
        let mut ctr = vec![];
        ctr.extend_from_slice(&nonce.to_le_bytes());
        ctr.extend_from_slice(&(idx as u64).to_le_bytes());
        let mut keystream = encrypt_aes_ecb(&ctr, key)?;
        keystream.truncate(block.len());
        out.extend_from_slice(&keystream.xor(block));
    }
    Ok(out)
}

pub fn decrypt_aes_ctr(bytes: &[u8], key: &[u8], nonce: u64) -> Result<Vec<u8>> {
    stream_aes_ctr(bytes, key, nonce)
}

pub fn decrypt_aes_cbc(bytes: &[u8], iv: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let block_size = 16;
    ensure!(
        bytes.len() % block_size == 0,
        "expected multiple of {block_size}, got {}",
        bytes.len()
    );
    let mut iv = iv;
    let mut decrypted = vec![];
    for block in bytes.chunks_exact(block_size) {
        let decrypted_block = decrypt_aes_cbc_block(block, iv, key)?;
        decrypted.extend(decrypted_block);
        iv = block;
    }

    decrypted.validate_unpad_pkcs7()
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

pub fn break_ecb(oracle: &impl EncryptingOracle) -> anyhow::Result<Vec<u8>> {
    let blocksize = detect_block_size(oracle)?;
    ensure_ecb(blocksize, oracle)?;
    let alignment = detect_alignment(blocksize, oracle)?;
    let encrypt_len = detect_payload_length(blocksize, &alignment, oracle)?;
    let mut decrypted = vec![];
    for _ in 0..encrypt_len {
        let byte = decrypt_next_byte(&alignment, blocksize, &decrypted, oracle)?;
        decrypted.push(byte);
    }

    Ok(decrypted)
}

fn detect_block_size(oracle: &impl EncryptingOracle) -> anyhow::Result<usize> {
    for len in 2..=255 {
        let plaintext = vec![b'0'; len * 4];
        let encrypted = oracle.encrypt(&plaintext)?;

        for (a, b, c) in encrypted.chunks(len).tuple_windows::<(_, _, _)>() {
            if a == b && b == c {
                return Ok(len);
            }
        }
    }
    bail!("Could not detect block size");
}

fn ensure_ecb(blocksize: usize, oracle: &impl EncryptingOracle) -> anyhow::Result<()> {
    let plaintext = vec![b'A'; blocksize * 3];
    let encrypted = oracle.encrypt(&plaintext)?;
    ensure!(detect_aes_128_ecb(&encrypted), "expected to confirm ecb");
    Ok(())
}

fn detect_payload_length(
    blocksize: usize,
    alignment: &Alignment,
    oracle: &impl EncryptingOracle,
) -> anyhow::Result<usize> {
    // The payload is pkcs7 padded, so the encrypt length will always be a multiple
    // of the blocksize.
    // Keep adding a byte at a time to the plaintext len until the ciphertext
    // jumps by blocksize -- that was the number of padding bytes added to the original plaintext
    let prefix = vec![b'A'; alignment.len];
    let curlen = oracle.encrypt(&prefix)?.len();

    let mut bytes = prefix;
    for padlen in 0..blocksize {
        bytes.truncate(alignment.len);
        bytes.extend(vec![b'A'; padlen]);
        let len = oracle.encrypt(&bytes)?.len();
        if len != curlen {
            let payload_len = curlen - padlen - alignment.block_idx * blocksize;
            return Ok(payload_len);
        }
    }
    bail!("Did not find a length");
}

fn decrypt_next_byte(
    alignment: &Alignment,
    blocksize: usize,
    decrypted: &[u8],
    oracle: &impl EncryptingOracle,
) -> anyhow::Result<u8> {
    let mut prefix = vec![];
    while (prefix.len() + decrypted.len()) % blocksize != (blocksize - 1) {
        prefix.push(b'A');
    }
    let mut plaintext = vec![];
    plaintext.extend(&prefix);
    plaintext.extend(decrypted);

    ensure!(plaintext.len() >= (blocksize - 1));
    ensure!(plaintext.len() % blocksize == (blocksize - 1));
    let mut probe_prefix = plaintext[plaintext.len() - (blocksize - 1)..].to_vec();

    for &probe_byte in BYTES_BY_FREQ.iter() {
        probe_prefix.truncate(blocksize - 1);
        probe_prefix.push(probe_byte);
        let probe = &probe_prefix;

        ensure!(probe.len() == blocksize);

        let mut bytes = vec![];
        bytes.extend(vec![b'0'; alignment.len]);
        bytes.extend(probe);
        bytes.extend(&plaintext);
        bytes.truncate(bytes.len() - decrypted.len());

        let probe_block_idx = alignment.block_idx;
        let target_block_idx = probe_block_idx + ((1 + plaintext.len()) / blocksize);
        let encrypted = oracle.encrypt(&bytes)?;

        let probe_block = encrypted.chunks(blocksize).nth(probe_block_idx).unwrap();
        let target_block = encrypted.chunks(blocksize).nth(target_block_idx).unwrap();

        if probe_block == target_block {
            return Ok(probe_byte);
        }
    }

    bail!("failed to decrypt a byte");
}

#[derive(Debug, Default)]
struct Alignment {
    len: usize,
    block_idx: usize,
}

fn detect_alignment(blocksize: usize, oracle: &impl EncryptingOracle) -> anyhow::Result<Alignment> {
    let plaintext_block = bytes::rand_of_len(blocksize);
    for len in 0..blocksize {
        let align_bytes = bytes::rand_of_len(len);
        let mut bytes = vec![];
        bytes.extend(&align_bytes);
        bytes.extend(&plaintext_block);
        bytes.extend(&plaintext_block);

        let encrypted = oracle.encrypt(&bytes)?;
        for (block_idx, (a, b)) in encrypted
            .chunks(blocksize)
            .tuple_windows::<(_, _)>()
            .enumerate()
        {
            if a == b {
                return Ok(Alignment { len, block_idx });
            }
        }
    }
    bail!("Could not detect prefix len");
}

pub fn break_ecb_cut_paste(oracle: &ProfileOracle) -> anyhow::Result<Vec<u8>> {
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

pub fn break_cbc_bitflip(oracle: &CbcOracle) -> anyhow::Result<Vec<u8>> {
    let blocksize = 16;
    let plaintext = vec![b'A'; blocksize * 2];
    let encrypted = oracle.encrypt(&plaintext)?;
    let mut patched = vec![];
    for (idx, block) in encrypted.chunks(blocksize).enumerate() {
        if idx == 2 {
            let data = ";admin=true;".as_bytes().to_vec();
            let patch = data.xor(&vec![b'A'; blocksize]);
            patched.extend(block.xor(&patch));
        } else {
            patched.extend(block);
        }
    }
    Ok(patched)
}

pub fn break_cbc_padding_oracle(oracle: &CbcPaddingOracle) -> anyhow::Result<Vec<u8>> {
    let blocksize = 16;
    let ciphertext = oracle.ciphertext.clone();

    fn break_block(
        prev_block: &[u8],
        block: &[u8],
        oracle: &CbcPaddingOracle,
    ) -> anyhow::Result<Vec<u8>> {
        let blocksize = 16;
        let mut probe_block = prev_block.to_vec();
        let mut cleartext = vec![0; blocksize];

        for byte_rhs_offset in 0..blocksize {
            let byte_idx = blocksize - byte_rhs_offset - 1;
            let pad_target: u8 = byte_rhs_offset as u8 + 1;

            for pad_byte_idx in (byte_idx + 1)..blocksize {
                probe_block[pad_byte_idx] =
                    prev_block[pad_byte_idx] ^ cleartext[pad_byte_idx] ^ pad_target;
            }

            let cipher_byte = prev_block[byte_idx];
            let mut possible_probe_bytes = vec![];

            for probe_byte in u8::MIN..=u8::MAX {
                probe_block[byte_idx] = probe_byte;
                let mut ciphertext = vec![];
                ciphertext.extend_from_slice(&probe_block);
                ciphertext.extend_from_slice(block);
                if oracle.check_padding(&ciphertext)? {
                    // last byte of decrypted (lbd) == pad_target
                    // lbd = intermediate ^ prev_block[byte]
                    // prev_block[byte] ^ pad_target = intermediate[byte]
                    // dbg!((
                    //     probe_byte,
                    //     block[byte_idx],
                    //     pad_target,
                    //     cipher_byte,
                    //     probe_byte ^ pad_target ^ cipher_byte,
                    //     &cleartext
                    // ));
                    let plaintext_byte = probe_byte ^ pad_target ^ cipher_byte;
                    possible_probe_bytes.push((probe_byte, pad_target, plaintext_byte));
                }
            }
            if possible_probe_bytes.len() == 1 {
                let (_, _pad_target, plaintext_byte) = possible_probe_bytes[0];
                cleartext[byte_idx] = plaintext_byte;
            } else if possible_probe_bytes.len() == 2 {
                let equals_byte = possible_probe_bytes.iter().find(
                    |&(_probe_byte, pad_target, plaintext_byte)| pad_target == plaintext_byte,
                );
                ensure!(equals_byte.is_some());
                let unequals_byte = possible_probe_bytes.iter().find(
                    |&(_probe_byte, pad_target, plaintext_byte)| pad_target != plaintext_byte,
                );
                ensure!(unequals_byte.is_some());
                let plaintext_byte = unequals_byte.unwrap().2;
                cleartext[byte_idx] = plaintext_byte;
            } else {
                bail!("unknown state");
            }
        }

        Ok(cleartext)
    }

    let iv = oracle.iv.to_owned();
    let chunks = ciphertext.chunks(blocksize).map(|x| x.to_vec());
    let prev_blocks = once(iv).chain(chunks);
    let cur_blocks = ciphertext.chunks(blocksize).map(|x| x.to_vec());

    let mut cleartext = vec![];

    for (prev_block, cur_block) in prev_blocks.zip(cur_blocks) {
        let out = break_block(&prev_block, &cur_block, oracle)?;
        cleartext.extend(out);
    }

    Ok(cleartext.unpad_pkcs7())
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
