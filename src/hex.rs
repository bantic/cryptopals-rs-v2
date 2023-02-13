type Byte = u8;

pub trait ToHexStr {
    fn to_hex(&self) -> String;
}

pub trait ToHexBytes {
    fn to_hex_bytes(&self) -> Vec<u8>;
}

impl ToHexBytes for &str {
    fn to_hex_bytes(&self) -> Vec<u8> {
        from_str(self)
    }
}

impl ToHexStr for &[u8] {
    fn to_hex(&self) -> String {
        to_str(self)
    }
}

impl ToHexStr for Vec<u8> {
    fn to_hex(&self) -> String {
        to_str(self)
    }
}

fn from_str(s: &str) -> Vec<u8> {
    s.as_bytes()
        .iter()
        .map(ascii_byte_to_u8)
        .collect::<Vec<u8>>()
        .chunks_exact(2)
        .map(|a| {
            dbg!(a);
            dbg!((a[0] << 4) | a[1])
        })
        .collect()
}

fn ascii_byte_to_u8(b: &u8) -> u8 {
    match b {
        48..=57 => b - 48,
        97..=102 => b - 97 + 10,
        _ => panic!("Unexpected ascii byte {b}"),
    }
}

fn to_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|&b| byte_to_str(b))
        .map(|b| match b {
            0 => "0",
            1 => "1",
            2 => "2",
            3 => "3",
            4 => "4",
            5 => "5",
            6 => "6",
            7 => "7",
            8 => "8",
            9 => "9",
            10 => "a",
            11 => "b",
            12 => "c",
            13 => "d",
            14 => "e",
            15 => "f",
            _ => panic!("Unexpected byte {b}"),
        })
        .collect::<String>()
}

fn byte_to_str(b: Byte) -> [u8; 2] {
    [b >> 4, b & 0x0f]
}

#[cfg(test)]
mod tests {
    use crate::hex::ToHexBytes;
    use crate::hex::ToHexStr;

    #[test]
    fn test_from_str() {
        assert_eq!("00".to_hex_bytes(), vec![0]);
        assert_eq!("01".to_hex_bytes(), vec![1]);
        assert_eq!("09".to_hex_bytes(), vec![9]);
        assert_eq!("0a".to_hex_bytes(), vec![10]);
        assert_eq!("0b".to_hex_bytes(), vec![11]);
        assert_eq!("0f".to_hex_bytes(), vec![15]);
        assert_eq!("10".to_hex_bytes(), vec![16]);
        assert_eq!("1f".to_hex_bytes(), vec![31]);
        assert_eq!("20".to_hex_bytes(), vec![32]);

        assert_eq!("2020".to_hex_bytes(), vec![32, 32]);
        assert_eq!("200f".to_hex_bytes(), vec![32, 15]);
    }

    #[test]
    fn test_to_str() {
        assert_eq!(vec![0].to_hex(), "00");
        assert_eq!(vec![1].to_hex(), "01");
        assert_eq!(vec![9].to_hex(), "09");
        assert_eq!(vec![10].to_hex(), "0a");
        assert_eq!(vec![11].to_hex(), "0b");
        assert_eq!(vec![12].to_hex(), "0c");
        assert_eq!(vec![15].to_hex(), "0f");
        assert_eq!(vec![16].to_hex(), "10");
        assert_eq!(vec![31].to_hex(), "1f");
        assert_eq!(vec![32].to_hex(), "20");
        assert_eq!(vec![32, 32].to_hex(), "2020");
        assert_eq!(vec![32, 15].to_hex(), "200f");
    }
}
