const CHALLENGE2_LHS: &str = "1c0111001f010100061a024b53535009181c";
const CHALLENGE2_RHS: &str = "686974207468652062756c6c277320657965";
const CHALLENGE2_EXPECTED: &str = "746865206b696420646f6e277420706c6179";
const CHALLENGE3_CIPHER: &str =
    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
const CHALLENGE5_INPUT: &str =
    "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
const CHALLENGE5_KEY: &str = "ICE";
const CHALLENGE6_INPUT: &str = include_str!("../files/6.txt");
const CHALLENGE7_INPUT: &str = include_str!("../files/7.txt");
const CHALLENGE7_KEY: &[u8] = "YELLOW SUBMARINE".as_bytes();
const CHALLENGE8_INPUT: &str = include_str!("../files/8.txt");

use crate::{
    aes, base64,
    hex::{DecodeHex, EncodeHex},
    utils,
    xor::{break_repeating_key_xor, break_single_key, break_single_key_multilines, Xor},
};
use anyhow::Result;

fn challenge2() {
    let out = CHALLENGE2_LHS
        .decode_hex()
        .xor(&CHALLENGE2_RHS.decode_hex())
        .to_hex();
    assert_eq!(out, CHALLENGE2_EXPECTED);
    println!("✅ Challenge 2:\n\t{CHALLENGE2_LHS} xor {CHALLENGE2_RHS} =>\n\t{out}");
}

fn challenge3() {
    let bytes = CHALLENGE3_CIPHER.decode_hex();
    let out = break_single_key(&bytes);
    println!("✅ Challenge 3:\n\t{CHALLENGE3_CIPHER} break single-key xor =>\n\t{out}");
}

fn challenge4() {
    let input = include_str!("../files/set-1-challenge-4.txt");
    let out = break_single_key_multilines(input);
    let out = out.trim_end();

    println!("✅ Challenge 4:\n\t{out}");
}

fn challenge5() {
    let bytes = CHALLENGE5_INPUT.as_bytes();
    let key = CHALLENGE5_KEY.as_bytes();
    let out = bytes.xor(key);
    let out = out.to_hex();
    println!("✅ Challenge 5:\n\t{out}");
}

fn challenge6() {
    let input = base64::from_file_str(CHALLENGE6_INPUT);
    let decoded = break_repeating_key_xor(&input);
    println!(
        "✅ Challenge 6:\n\t{}",
        utils::truncate(String::from_utf8_lossy(&decoded).into())
    );
}

fn challenge7() -> Result<()> {
    let input = base64::from_file_str(CHALLENGE7_INPUT);
    let decoded = aes::decrypt_aes_ecb(&input, CHALLENGE7_KEY)?;
    println!(
        "✅ Challenge 7:\n\t{}",
        utils::truncate(String::from_utf8_lossy(&decoded).into())
    );
    Ok(())
}

fn challenge8() {
    println!("✅ Challenge 8: Detect AES 128 ECB");
    let input = CHALLENGE8_INPUT;
    for line in input.lines() {
        let line = line.trim();
        let bytes = line.decode_hex();
        if aes::detect_aes_128_ecb(&bytes) {
            println!("\t{line} is aes-128-ecb");
        }
    }
}

pub fn main() -> Result<()> {
    println!("\n========= Set 1 =======\n-----------------------");
    challenge2();
    challenge3();
    challenge4();
    challenge5();
    challenge6();
    challenge7()?;
    challenge8();
    Ok(())
}

#[cfg(test)]
mod tests {
    const CHALLENGE5_EXPECTED: &str= "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    const CHALLENGE3_EXPECTED: &str = "Cooking MC's like a pound of bacon";
    const CHALLENGE6_EXPECTED: &str = include_str!("../files/funky_music_lyrics.txt");
    const CHALLENGE7_EXPECTED: &str = include_str!("../files/funky_music_lyrics.txt");
    const CHALLENGE8_EXPECTED: &str = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";

    use crate::{
        aes, base64,
        hex::{DecodeHex, EncodeHex},
        sets::set1::{
            CHALLENGE2_EXPECTED, CHALLENGE2_LHS, CHALLENGE2_RHS, CHALLENGE3_CIPHER,
            CHALLENGE5_INPUT, CHALLENGE5_KEY, CHALLENGE6_INPUT, CHALLENGE7_INPUT, CHALLENGE7_KEY,
            CHALLENGE8_INPUT,
        },
        xor::{break_repeating_key_xor, break_single_key, break_single_key_multilines, Xor},
    };

    #[test]
    fn test_challenge2() {
        let out = CHALLENGE2_LHS
            .decode_hex()
            .xor(&CHALLENGE2_RHS.decode_hex())
            .to_hex();
        assert_eq!(out, CHALLENGE2_EXPECTED);
    }

    #[test]
    fn test_challenge3() {
        let out = break_single_key(&CHALLENGE3_CIPHER.decode_hex());
        assert_eq!(out, CHALLENGE3_EXPECTED);
    }

    #[test]
    fn test_challenge4() {
        let input = include_str!("../files/set-1-challenge-4.txt");
        let out = break_single_key_multilines(input);
        assert_eq!(out, "Now that the party is jumping\n");
    }

    #[test]
    fn test_challenge5() {
        let bytes = CHALLENGE5_INPUT.as_bytes();
        let key = CHALLENGE5_KEY.as_bytes();
        let out = bytes.xor(key);
        let out = out.to_hex();
        assert_eq!(out, CHALLENGE5_EXPECTED);
    }

    #[test]
    fn test_challenge6() {
        let input = base64::from_file_str(CHALLENGE6_INPUT);
        let decoded = break_repeating_key_xor(&input);
        let decoded = String::from_utf8_lossy(&decoded);
        assert_eq!(decoded, CHALLENGE6_EXPECTED);
    }

    #[test]
    fn test_challenge7() -> anyhow::Result<()> {
        let input = base64::from_file_str(CHALLENGE7_INPUT);
        let decoded = aes::decrypt_aes_ecb(&input, CHALLENGE7_KEY)?;
        let decoded = String::from_utf8_lossy(&decoded);
        assert_eq!(decoded, CHALLENGE7_EXPECTED);
        Ok(())
    }

    #[test]

    fn test_challenge8() {
        let input = CHALLENGE8_INPUT;
        let mut results = vec![];
        for line in input.lines() {
            let line = line.trim();
            let bytes = line.decode_hex();
            if aes::detect_aes_128_ecb(&bytes) {
                results.push(line);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results.first(), Some(&CHALLENGE8_EXPECTED));
    }
}
