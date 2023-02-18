use anyhow::Result;
use openssl::symm::{decrypt, Cipher};

pub fn decrypt_aes_ecb(bytes: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_128_ecb();
    decrypt(cipher, key, None, bytes).map_err(anyhow::Error::from)
}
