pub mod set1 {
    const CHALLENGE2_LHS: &str = "1c0111001f010100061a024b53535009181c";
    const CHALLENGE2_RHS: &str = "686974207468652062756c6c277320657965";
    const CHALLENGE2_EXPECTED: &str = "746865206b696420646f6e277420706c6179";
    const CHALLENGE3_CIPHER: &str =
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const CHALLENGE3_EXPECTED: &str = "Cooking MC's like a pound of bacon";
    const CHALLENGE5_INPUT: &str =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const CHALLENGE5_EXPECTED: &str= "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    const CHALLENGE5_KEY: &str = "ICE";
    const CHALLENGE6_INPUT: &str = include_str!("../files/6.txt");
    const CHALLENGE6_EXPECTED: &str = include_str!("../files/6.expected.txt");

    use crate::{
        base64::DecodeBase64,
        hex::{ToHexBytes, ToHexStr},
        xor::{break_repeating_key_xor, break_single_key, break_single_key_multilines, Xor},
    };

    pub fn challenge2() {
        let out = CHALLENGE2_LHS
            .to_hex_bytes()
            .xor(&CHALLENGE2_RHS.to_hex_bytes())
            .to_hex();
        assert_eq!(out, CHALLENGE2_EXPECTED);
        println!("✅ Set 1 Challenge 2:\n\t{CHALLENGE2_LHS} xor {CHALLENGE2_RHS} =>\n\t{out}");
    }

    pub fn challenge3() {
        let bytes = CHALLENGE3_CIPHER.to_hex_bytes();
        let out = break_single_key(&bytes);
        println!("✅ Set 1 Challenge 3:\n\t{CHALLENGE3_CIPHER} break single-key xor =>\n\t{out}");
    }

    pub fn challenge4() {
        let input = include_str!("../files/set-1-challenge-4.txt");
        let out = break_single_key_multilines(input);
        let out = out.trim_end();

        println!("✅ Set 1 Challenge 4:\n\t{out}");
    }

    pub fn challenge5() {
        let bytes = CHALLENGE5_INPUT.as_bytes();
        let key = CHALLENGE5_KEY.as_bytes();
        let out = bytes.xor(key);
        let out = out.to_hex();
        println!("✅ Set 1 Challenge 5:\n\t{out}");
    }

    pub fn challenge6() {
        let input: String = CHALLENGE6_INPUT.lines().map(|l| l.trim()).collect();
        let input = input.as_str().decode_base64();
        let decoded = break_repeating_key_xor(&input);
        println!(
            "✅ Set 1 Challenge 6:\n{}",
            String::from_utf8_lossy(&decoded)
        );
    }

    #[cfg(test)]
    mod tests {
        use crate::{
            base64::DecodeBase64,
            hex::{ToHexBytes, ToHexStr},
            sets::set1::{
                CHALLENGE2_EXPECTED, CHALLENGE2_LHS, CHALLENGE2_RHS, CHALLENGE3_CIPHER,
                CHALLENGE3_EXPECTED, CHALLENGE5_EXPECTED, CHALLENGE5_INPUT, CHALLENGE5_KEY,
                CHALLENGE6_EXPECTED, CHALLENGE6_INPUT,
            },
            xor::{break_repeating_key_xor, break_single_key, break_single_key_multilines, Xor},
        };

        #[test]
        fn test_challenge2() {
            let out = CHALLENGE2_LHS
                .to_hex_bytes()
                .xor(&CHALLENGE2_RHS.to_hex_bytes())
                .to_hex();
            assert_eq!(out, CHALLENGE2_EXPECTED);
        }

        #[test]
        fn test_challenge3() {
            let out = break_single_key(&CHALLENGE3_CIPHER.to_hex_bytes());
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
            let input: String = CHALLENGE6_INPUT.lines().map(|l| l.trim()).collect();
            let input = input.as_str().decode_base64();
            let decoded = break_repeating_key_xor(&input);
            let decoded = String::from_utf8_lossy(&decoded);
            assert_eq!(decoded, CHALLENGE6_EXPECTED);
        }
    }
}
