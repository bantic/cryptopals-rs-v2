// A value outside the b64 range to avoid conflicting
// with the value 61.
// This value signifies to put a padding '=' in the output
const PAD_ENCODE: u8 = 65;

pub trait ToBase64 {
    fn to_base64(&self) -> String;
}

impl ToBase64 for &[u8] {
    fn to_base64(&self) -> String {
        bytes_to_b64_str(self)
    }
}

impl ToBase64 for &str {
    fn to_base64(&self) -> String {
        self.as_bytes().to_base64()
    }
}

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
    use crate::base64::ToBase64;

    #[test]
    fn test_to_base64() {
        assert_eq!("Man".to_base64(), "TWFu");
        assert_eq!("Man".to_base64(), "TWFu");
        assert_eq!("Ma".to_base64(), "TWE=");
        assert_eq!("M".to_base64(), "TQ==");
        assert_eq!("light work.".to_base64(), "bGlnaHQgd29yay4=");
        assert_eq!("light work".to_base64(), "bGlnaHQgd29yaw==");
        assert_eq!("light wor".to_base64(), "bGlnaHQgd29y");
        assert_eq!("light wo".to_base64(), "bGlnaHQgd28=");
    }
}
