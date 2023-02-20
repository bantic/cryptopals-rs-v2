use crate::utils::bytes;

pub trait PadPkcs7 {
    fn pad_pkcs7(&self) -> Vec<u8>;
}

pub trait UnpadPkcs7 {
    fn unpad_pkcs7(&self) -> Vec<u8>;
}

impl PadPkcs7 for &[u8] {
    fn pad_pkcs7(&self) -> Vec<u8> {
        pad_pkcs7(self)
    }
}

impl PadPkcs7 for Vec<u8> {
    fn pad_pkcs7(&self) -> Vec<u8> {
        pad_pkcs7(self)
    }
}

fn pad_pkcs7(data: &[u8]) -> Vec<u8> {
    let block_size = 16;
    let rem = 16 - data.len() % block_size;

    let mut padded = data.to_vec();
    padded.extend(bytes::of_len(rem, rem as u8));
    padded
}

impl UnpadPkcs7 for &[u8] {
    fn unpad_pkcs7(&self) -> Vec<u8> {
        unpad_pkcs7(self)
    }
}

impl UnpadPkcs7 for Vec<u8> {
    fn unpad_pkcs7(&self) -> Vec<u8> {
        unpad_pkcs7(self)
    }
}

fn unpad_pkcs7(data: &[u8]) -> Vec<u8> {
    let block_size = 16;
    if data.len() % block_size != 0 {
        panic!(
            "Cannot unpad when length is not multiple of {}, len: {}",
            block_size,
            data.len()
        );
    }
    if data.is_empty() {
        vec![]
    } else {
        let &last = data.last().unwrap();
        let mut unpadded = data.to_vec();
        unpadded.truncate(data.len() - last as usize);
        unpadded
    }
}

#[cfg(test)]
mod tests {
    use crate::{hex::DecodeHex, padding::UnpadPkcs7, utils::bytes};

    use super::PadPkcs7;

    #[test]
    fn test_pad() {
        assert_eq!(
            "74657374696e67".decode_hex().pad_pkcs7(),
            "74657374696e67090909090909090909".decode_hex()
        );

        assert_eq!(
            "74657374696e6731".decode_hex().pad_pkcs7(),
            "74657374696e67310808080808080808".decode_hex()
        );

        let mut expected = "YELLOW SUBMARINE".as_bytes().to_vec();
        expected.extend(bytes::of_len(16, 16));
        assert_eq!("YELLOW SUBMARINE".as_bytes().pad_pkcs7(), expected);
    }

    #[test]
    fn test_unpad() {
        assert_eq!(
            "74657374696e67090909090909090909"
                .decode_hex()
                .unpad_pkcs7(),
            "74657374696e67".decode_hex()
        );

        assert_eq!(
            "74657374696e67310808080808080808"
                .decode_hex()
                .unpad_pkcs7(),
            "74657374696e6731".decode_hex()
        );

        let padded = "YELLOW SUBMARINE".as_bytes().pad_pkcs7();
        assert_eq!(padded.unpad_pkcs7(), "YELLOW SUBMARINE".as_bytes());
    }
}