// A value outside the b64 range to avoid conflicting
// with the value 61.
// This value signifies to put a padding '=' in the output
const PAD_ENCODE: u8 = 65;

pub trait ToBase64 {
    fn to_base64(&self) -> String;
}

pub trait DecodeBase64 {
    fn decode_base64(&self) -> Vec<u8>;
}

impl DecodeBase64 for &str {
    fn decode_base64(&self) -> Vec<u8> {
        decode_base64(self)
    }
}

impl DecodeBase64 for &String {
    fn decode_base64(&self) -> Vec<u8> {
        decode_base64(self.as_str())
    }
}

fn decode_base64(s: &str) -> Vec<u8> {
    let sextets: Vec<u8> = s.chars().map(char_to_b64_sextet).collect();
    dbg!(&sextets);
    sextets
        .chunks(4)
        .flat_map(|chunk| {
            dbg!(chunk);
            match chunk {
                [a, b, PAD_ENCODE, PAD_ENCODE] => {
                    vec![((a & 0b00111111) << 2) | ((b & 0b00110000) >> 4)]
                }
                [a, b, c, PAD_ENCODE] => vec![
                    ((a & 0b00111111) << 2) | ((b & 0b00110000) >> 4),
                    ((b & 0b00001111) << 4) | ((c & 0b00111100) >> 2),
                ],
                [a, b, c, d] => dbg!(vec![
                    ((a & 0b00111111) << 2) | ((b & 0b00110000) >> 4),
                    ((b & 0b00001111) << 4) | ((c & 0b00111100) >> 2),
                    ((c & 0b00000011) << 6) | (d & 0b00111111),
                ]),
                _ => panic!("Unexpected chunk {:?}", chunk),
            }
        })
        .collect()
}

impl ToBase64 for &[u8] {
    fn to_base64(&self) -> String {
        bytes_to_b64_str(self)
    }
}

impl ToBase64 for Vec<u8> {
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

fn bin_bytes_to_b64_sextets(bytes: &[u8]) -> Vec<u8> {
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

fn char_to_b64_sextet(ch: char) -> u8 {
    match ch {
        'A'..='Z' => ch as u8 - 65,      // 0-25
        'a'..='z' => ch as u8 - 97 + 26, // 26-51
        '0'..='9' => ch as u8 - 48 + 52, // 52-61
        '+' => 62,
        '/' => 63,
        '=' => PAD_ENCODE,
        _ => panic!("Unexpected b64 char {ch}"),
    }
}

fn b64_sextet_to_char(b: &u8) -> char {
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
    bin_bytes_to_b64_sextets(bytes)
        .iter()
        .map(b64_sextet_to_char)
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::base64::{DecodeBase64, ToBase64};

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

    #[test]
    fn test_decode_base64() {
        assert_eq!("TWFu".decode_base64(), "Man".as_bytes());
        assert_eq!("TWE=".decode_base64(), "Ma".as_bytes());
        assert_eq!("TQ==".decode_base64(), "M".as_bytes());

        fn rand_bytes(len: usize) -> Vec<u8> {
            (0..=len).map(|_| rand::random()).collect()
        }

        // generate 10 random vecs for each len and assert
        // decode(encode) is correct
        for len in 5..=10 {
            for _ in 0..=10 {
                let bytes = rand_bytes(len);
                let b64 = &bytes.to_base64();
                assert_eq!(b64.decode_base64(), bytes);
            }
        }
    }
}
