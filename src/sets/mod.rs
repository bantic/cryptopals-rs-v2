pub mod set1 {
    const CHALLENGE2_LHS: &str = "1c0111001f010100061a024b53535009181c";
    const CHALLENGE2_RHS: &str = "686974207468652062756c6c277320657965";
    const CHALLENGE2_EXPECTED: &str = "746865206b696420646f6e277420706c6179";

    use crate::{
        hex::{ToHexBytes, ToHexStr},
        xor::Xor,
    };

    pub fn challenge2() {
        let out = CHALLENGE2_LHS
            .to_hex_bytes()
            .xor(&CHALLENGE2_RHS.to_hex_bytes())
            .to_hex();
        assert_eq!(out, CHALLENGE2_EXPECTED);
        println!("✅ Set 1 Challenge 2:\n\t{CHALLENGE2_LHS} xor {CHALLENGE2_RHS} =>\n\t{out}");
    }

    #[cfg(test)]
    mod tests {
        use crate::{
            hex::{ToHexBytes, ToHexStr},
            sets::set1::{CHALLENGE2_EXPECTED, CHALLENGE2_LHS, CHALLENGE2_RHS},
            xor::Xor,
        };

        #[test]
        fn test_challenge2() {
            let out = CHALLENGE2_LHS
                .to_hex_bytes()
                .xor(&CHALLENGE2_RHS.to_hex_bytes())
                .to_hex();
            assert_eq!(out, CHALLENGE2_EXPECTED);
        }
    }
}
