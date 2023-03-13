use crate::{
    aes::{break_cbc_padding_oracle, decrypt_aes_ctr},
    base64::DecodeBase64,
    oracle::CbcPaddingOracle,
};
use anyhow::Result;

fn challenge17() -> Result<()> {
    println!("Challenge 17: Break CBC with a padding oracle");
    let b64_plaintexts = include_str!("../files/cbc-plaintexts-b64.txt");
    for line in b64_plaintexts.lines() {
        let plaintext = line.trim().decode_base64();
        let oracle = CbcPaddingOracle::new(plaintext)?;
        let result = break_cbc_padding_oracle(&oracle)?;

        let emoji = if oracle.verify(&result) { "✅" } else { "❌" };
        println!("{emoji} {}", String::from_utf8(result)?);
    }
    Ok(())
}

fn challenge18() -> Result<()> {
    println!("Challenge 18: CTR");
    let ciphertext =
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".decode_base64();
    let nonce: u64 = 0;
    let key = "YELLOW SUBMARINE".as_bytes();
    let plaintext = decrypt_aes_ctr(&ciphertext, key, nonce)?;
    println!("✅ {}", String::from_utf8(plaintext)?);
    Ok(())
}

pub fn main() -> Result<()> {
    println!("\n========= Set 3 =======\n-----------------------");
    challenge17()?;
    challenge18()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        aes::{break_cbc_padding_oracle, decrypt_aes_ctr, encrypt_aes_ctr},
        base64::DecodeBase64,
        oracle::CbcPaddingOracle,
        utils::bytes,
    };
    use anyhow::Result;
    use rand::Rng;

    #[test]
    fn test_challenge17() -> Result<()> {
        let b64_plaintexts = include_str!("../files/cbc-plaintexts-b64.txt");
        for line in b64_plaintexts.lines() {
            let plaintext = line.trim().decode_base64();
            let oracle = CbcPaddingOracle::new(plaintext)?;
            let result = break_cbc_padding_oracle(&oracle)?;
            assert!(oracle.verify(&result));
        }
        Ok(())
    }
    #[test]
    fn test_challenge18() -> Result<()> {
        let mut rng = rand::thread_rng();

        let ciphertext = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
            .decode_base64();
        let nonce: u64 = 0;
        let key = "YELLOW SUBMARINE".as_bytes();
        let plaintext = decrypt_aes_ctr(&ciphertext, key, nonce)?;

        assert_eq!(
            String::from_utf8(plaintext)?,
            "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
        );

        for _ in 0..=100 {
            let blocksize = 16;
            let len = rng.gen_range(16..=100);
            let plaintext = bytes::rand_of_len(len);
            let key = bytes::rand_of_len(blocksize);
            let nonce: u64 = rand::random();
            let ciphertext = encrypt_aes_ctr(&plaintext, &key, nonce)?;
            let decrypted = decrypt_aes_ctr(&ciphertext, &key, nonce)?;

            assert_eq!(decrypted, plaintext);
        }

        Ok(())
    }
}
