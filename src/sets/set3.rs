use crate::{
    aes::{break_cbc_padding_oracle, decrypt_aes_ctr, encrypt_aes_ctr},
    base64::DecodeBase64,
    mersenne::Mt19937,
    oracle::CbcPaddingOracle,
    utils::bytes,
    xor::{break_repeating_key_xor_with_keysize, Xor},
};
use anyhow::{ensure, Result};

fn challenge17() -> Result<()> {
    println!("Challenge 17: Break CBC with a padding oracle");
    let b64_plaintexts = include_str!("../files/cbc-plaintexts-b64.txt");
    for line in b64_plaintexts.lines() {
        let plaintext = line.trim().decode_base64();
        let oracle = CbcPaddingOracle::new(plaintext)?;
        let result = break_cbc_padding_oracle(&oracle)?;

        let emoji = if oracle.verify(&result) { "✅" } else { "❌" };
        println!("\t{emoji} {}", String::from_utf8(result)?);
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
    println!("\t ✅ {}", String::from_utf8(plaintext)?);
    Ok(())
}

fn challenge19_20() -> Result<bool> {
    println!("Challenge 19/20: Break Fixed-Nonce CTR");
    let b64_plaintexts = include_str!("../files/ctr-plaintexts-b64-20.txt");
    let blocksize = 16;
    let nonce: u64 = 0;
    let key = bytes::rand_of_len(blocksize);
    let mut ciphertexts = vec![];
    let mut plaintexts = vec![];
    for line in b64_plaintexts.lines() {
        let plaintext = line.trim().decode_base64();
        let ciphertext = encrypt_aes_ctr(&plaintext, &key, nonce)?;
        plaintexts.push(plaintext);
        ciphertexts.push(ciphertext);
    }

    let repeat_len = ciphertexts.iter().map(|b| b.len()).min().unwrap();
    let mut full_ciphertext = vec![];
    for ciphertext in ciphertexts {
        let slice = &ciphertext[0..repeat_len];
        ensure!(slice.len() == repeat_len);
        full_ciphertext.extend_from_slice(slice);
    }

    let broken_key = break_repeating_key_xor_with_keysize(&full_ciphertext, repeat_len);
    let full_plaintext = full_ciphertext.xor(&broken_key);
    let mut correct = 0;
    let mut incorrect = 0;
    for (plaintext, decrypted) in full_plaintext.chunks(repeat_len).zip(plaintexts) {
        if plaintext[..repeat_len] == decrypted[..repeat_len] {
            correct += 1;
        } else {
            incorrect += 1;
        }
    }

    if incorrect == 0 {
        println!("\t✅ {correct} / {correct} decrypted");
    } else {
        println!(
            "\t❌ {incorrect} / {} failed to decrypt correctly",
            correct + incorrect
        );
    }

    Ok(incorrect == 0)
}

fn challenge21() -> Result<()> {
    println!("Challenge 21: Implement mt19337");
    let mut rnd = Mt19937::new(Some(0));
    for _ in 0..=25 {
        println!("{}", rnd.gen());
    }
    Ok(())
}

pub fn main() -> Result<()> {
    println!("\n========= Set 3 =======\n-----------------------");
    challenge17()?;
    challenge18()?;
    challenge19_20()?;
    challenge21()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        aes::{break_cbc_padding_oracle, decrypt_aes_ctr, encrypt_aes_ctr},
        base64::DecodeBase64,
        oracle::CbcPaddingOracle,
        sets::set3::challenge19_20,
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

        for _ in 0..100 {
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
    #[test]
    fn test_challenge19() -> Result<()> {
        for _ in 0..10 {
            assert!(challenge19_20()?);
        }
        Ok(())
    }
}
