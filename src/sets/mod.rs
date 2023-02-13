pub mod set1 {
    const CHALLENGE2_LHS: &str = "1c0111001f010100061a024b53535009181c";
    const CHALLENGE2_RHS: &str = "686974207468652062756c6c277320657965";
    const CHALLENGE2_EXPECTED: &str = "746865206b696420646f6e277420706c6179";
    const CHALLENGE3_CIPHER: &str =
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const CHALLENGE3_EXPECTED: &str = "Cooking MC's like a pound of bacon";

    use crate::{
        hex::{ToHexBytes, ToHexStr},
        xor::{break_single_key, break_single_key_multilines, Xor},
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

        println!("✅ Set 1 Challenge 4:\n\t{out}");
    }

    #[cfg(test)]
    mod tests {
        use crate::{
            hex::{ToHexBytes, ToHexStr},
            sets::set1::{
                CHALLENGE2_EXPECTED, CHALLENGE2_LHS, CHALLENGE2_RHS, CHALLENGE3_CIPHER,
                CHALLENGE3_EXPECTED,
            },
            xor::{break_single_key, break_single_key_multilines, Xor},
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
    }
}
