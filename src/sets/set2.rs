use anyhow::ensure;

use crate::{
    aes::{self, break_cbc_bitflip, break_ecb, break_ecb_cut_paste},
    base64,
    oracle::{self, CbcOracle, PaddingOracle, PrefixPaddingOracle, ProfileOracle},
    padding::UnpadPkcs7,
    utils::{self, bytes},
};

const CHALLENGE10_INPUT: &str = include_str!("../files/10.txt");
const CHALLENGE12_INPUT: &str = include_str!("../files/12.txt");

fn challenge10() -> anyhow::Result<()> {
    let encrypted = base64::from_file_str(CHALLENGE10_INPUT);
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = &bytes::of_len(16, 0);
    let decrypted = aes::decrypt_aes_cbc(&encrypted, iv, key)?;
    println!(
        "✅ Challenge 10: AES CBC Mode\n\t{}",
        utils::truncate(String::from_utf8_lossy(&decrypted).into())
    );
    Ok(())
}

fn challenge11() -> anyhow::Result<()> {
    println!("✅ Challenge 11: ECB/CBC Detection Oracle");
    for i in 1..=5 {
        let oracle = oracle::encrypt(&[100; 48])?;
        let guess = oracle::guess(&oracle);
        let correct = if oracle.verify(&guess) { "✅" } else { "❌" };
        println!("\tAttempt #{i} {guess:?}: {correct}");
    }
    Ok(())
}

fn challenge12() -> anyhow::Result<()> {
    let secret = base64::from_file_str(CHALLENGE12_INPUT);
    let oracle = PaddingOracle::new(secret);
    let result = break_ecb(&oracle)?;
    ensure!(oracle.verify(&result));
    println!(
        "✅ Challenge 12: Break ECB using an Oracle (easy version)\n\t{}",
        utils::truncate(String::from_utf8_lossy(&result).into())
    );
    Ok(())
}

fn challenge13() -> anyhow::Result<()> {
    let oracle = ProfileOracle::new();
    let result = break_ecb_cut_paste(&oracle)?;

    println!(
        "✅ Challenge 13: Cut/Paste ECB to create fake admin profile\n\t{:?}",
        oracle.decrypt(&result)?
    );
    ensure!(oracle.verify(&result)?);

    Ok(())
}

fn challenge14() -> anyhow::Result<()> {
    let secret = base64::from_file_str(CHALLENGE12_INPUT);
    let oracle = PrefixPaddingOracle::new(secret);
    let result = break_ecb(&oracle)?;
    ensure!(oracle.verify(&result));
    println!(
        "✅ Challenge 14: Break Prefix-Padded ECB (hard version)\n\t{}",
        utils::truncate(String::from_utf8_lossy(&result).into())
    );
    Ok(())
}

fn challenge15() -> anyhow::Result<()> {
    ensure!("ICE ICE BABY\x04\x04\x04\x04"
        .as_bytes()
        .validate_unpad_pkcs7()
        .is_ok());
    ensure!("ICE ICE BABY\x04\x04\x04"
        .as_bytes()
        .validate_unpad_pkcs7()
        .is_err());
    ensure!("ICE ICE BABY\x05\x05\x05\x05"
        .as_bytes()
        .validate_unpad_pkcs7()
        .is_err());
    ensure!("ICE ICE BABY\x01\x02\x03\x04"
        .as_bytes()
        .validate_unpad_pkcs7()
        .is_err());

    println!("✅ Challenge 15: Detect Valid PKCS#7 Padding");

    Ok(())
}

fn challenge16() -> anyhow::Result<()> {
    let oracle = CbcOracle::new();
    let result = break_cbc_bitflip(&oracle)?;
    ensure!(oracle.verify(&result)?);
    println!("✅ Challenge 16: Break CBC by bitflipping");
    Ok(())
}

pub fn main() -> anyhow::Result<()> {
    println!("\n========= Set 2 =======\n-----------------------");
    challenge10()?;
    challenge11()?;
    challenge12()?;
    challenge13()?;
    challenge14()?;
    challenge15()?;
    challenge16()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        aes::{self, break_cbc_bitflip, break_ecb, break_ecb_cut_paste},
        base64,
        oracle::{self, CbcOracle, PaddingOracle, PrefixPaddingOracle, ProfileOracle},
        sets::set2::CHALLENGE12_INPUT,
        utils::bytes,
    };
    const CHALLENGE10_EXPECTED: &str = include_str!("../files/funky_music_lyrics.txt");
    const CHALLENGE12_EXPECTED: &str = include_str!("../files/rollin_lyrics.txt");

    use super::CHALLENGE10_INPUT;

    #[test]
    fn test_challenge10() -> anyhow::Result<()> {
        let encrypted = base64::from_file_str(CHALLENGE10_INPUT);
        let key = "YELLOW SUBMARINE".as_bytes();
        let iv = &bytes::of_len(16, 0);
        let binding = aes::decrypt_aes_cbc(&encrypted, iv, key)?;
        let decrypted = String::from_utf8_lossy(&binding);
        assert_eq!(decrypted, CHALLENGE10_EXPECTED);
        Ok(())
    }

    #[test]
    fn test_challenge11() -> anyhow::Result<()> {
        // 3x block size
        let plaintext = &[100; 16 * 3];
        for _ in 0..100 {
            let oracle = oracle::encrypt(plaintext)?;
            let guess = &oracle::guess(&oracle);
            assert!(oracle.verify(guess), "guess {:?}", guess);
        }
        Ok(())
    }

    #[test]
    fn test_challenge12() -> anyhow::Result<()> {
        for _ in 0..100 {
            let secret = base64::from_file_str(CHALLENGE12_INPUT);
            let oracle = PaddingOracle::new(secret);
            let result = break_ecb(&oracle)?;
            assert!(oracle.verify(&result));
        }
        Ok(())
    }

    #[test]
    fn test_challenge13() -> anyhow::Result<()> {
        for _ in 0..100 {
            let oracle = ProfileOracle::new();
            let result = break_ecb_cut_paste(&oracle)?;
            assert!(oracle.verify(&result)?);
        }
        Ok(())
    }

    #[test]
    fn test_challenge14() -> anyhow::Result<()> {
        // This fails about every now and again.
        // If the loop count is increased to 1000 it fails basically every time
        for _ in 0..50 {
            let secret = base64::from_file_str(CHALLENGE12_INPUT);
            let oracle = PrefixPaddingOracle::new(secret);
            let result = break_ecb(&oracle)?;
            assert_eq!(String::from_utf8_lossy(&result), CHALLENGE12_EXPECTED);
            assert!(oracle.verify(&result));
        }
        Ok(())
    }

    #[test]
    fn test_challenge16() -> anyhow::Result<()> {
        for _ in 0..100 {
            let oracle = CbcOracle::new();
            let result = break_cbc_bitflip(&oracle)?;
            assert!(oracle.verify(&result)?);
        }
        Ok(())
    }
}
