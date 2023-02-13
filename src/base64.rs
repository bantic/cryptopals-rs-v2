// A value outside the b64 range to avoid conflicting
// with the value 61.
// This value signifies to put a padding '=' in the output
const PAD_ENCODE: u8 = 65;

fn top_n_bits(x: &u8, n: u8) -> u8 {
    x >> (8 - n)
}

fn bottom_n_bits(x: &u8, n: u8) -> u8 {
    x & ((1 << n) - 1)
}

fn bin_bytes_to_b64_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes
        .chunks(3)
        .flat_map(|chunk| match chunk {
            [a, b, c] => [
                (top_n_bits(a, 6)),
                (((bottom_n_bits(a, 2)) << 4) | (top_n_bits(b, 4))),
                ((bottom_n_bits(b, 4) << 2) | (top_n_bits(c, 2))),
                (bottom_n_bits(c, 6)),
            ],
            [a, b] => [
                (top_n_bits(a, 6)),
                (((bottom_n_bits(a, 2)) << 4) | (top_n_bits(b, 4))),
                (bottom_n_bits(b, 4)) << 2,
                PAD_ENCODE,
            ],
            [a] => [
                top_n_bits(a, 6),
                bottom_n_bits(a, 2) << 4,
                PAD_ENCODE,
                PAD_ENCODE,
            ],
            _ => panic!("Unexpected chunk {:?}", chunk),
        })
        .collect()
}

fn b64_byte_to_char(b: &u8) -> char {
    (match b {
        0..=25 => b'A' + b,
        26..=51 => b'a' + b - 26,
        52..=61 => b'0' + b - 52,
        62 => b'+',
        63 => b'/',
        &PAD_ENCODE => b'=',
        _ => panic!("Unexpected b64 byte {b}"),
    }) as char
}

fn bytes_to_b64_str(bytes: &[u8]) -> String {
    bin_bytes_to_b64_bytes(bytes)
        .iter()
        .map(b64_byte_to_char)
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::base64::bytes_to_b64_str;

    #[test]
    fn test_to_base64() {
        assert_eq!(bytes_to_b64_str("Man".as_bytes()), "TWFu");
        assert_eq!(bytes_to_b64_str("Ma".as_bytes()), "TWE=");
        assert_eq!(bytes_to_b64_str("M".as_bytes()), "TQ==");
        assert_eq!(
            bytes_to_b64_str("light work.".as_bytes()),
            "bGlnaHQgd29yay4="
        );
        assert_eq!(
            bytes_to_b64_str("light work".as_bytes()),
            "bGlnaHQgd29yaw=="
        );
        assert_eq!(bytes_to_b64_str("light wor".as_bytes()), "bGlnaHQgd29y");
        assert_eq!(bytes_to_b64_str("light wo".as_bytes()), "bGlnaHQgd28=");
    }
}
