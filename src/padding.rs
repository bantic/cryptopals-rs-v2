use anyhow::ensure;

use crate::utils::bytes;

pub trait PadPkcs7 {
    fn pad_pkcs7(&self) -> Vec<u8>;
}

pub trait UnpadPkcs7 {
    fn unpad_pkcs7(&self) -> Vec<u8>;
    fn validate_unpad_pkcs7(&self) -> anyhow::Result<Vec<u8>>;
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

    fn validate_unpad_pkcs7(&self) -> anyhow::Result<Vec<u8>> {
        validate_unpad_pkcs7(self)
    }
}

impl UnpadPkcs7 for Vec<u8> {
    fn unpad_pkcs7(&self) -> Vec<u8> {
        unpad_pkcs7(self)
    }

    fn validate_unpad_pkcs7(&self) -> anyhow::Result<Vec<u8>> {
        validate_unpad_pkcs7(self)
    }
}

fn validate_unpad_pkcs7(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let blocksize = 16;
    ensure!(data.len() > 0);
    ensure!(data.len() % blocksize == 0);

    let last_byte = data[data.len() - 1];
    ensure!(last_byte <= blocksize as u8);
    ensure!(last_byte > 0);

    let expected = vec![last_byte; last_byte as usize];
    let ending = data
        .iter()
        .rev()
        .take(last_byte as usize)
        .copied()
        .collect::<Vec<_>>();
    ensure!(ending == expected);

    Ok(unpad_pkcs7(data))
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

    #[test]
    fn test_validate_unpad() {
        assert!("ICE ICE BABY\x04\x04\x04\x04"
            .as_bytes()
            .validate_unpad_pkcs7()
            .is_ok());
        assert!("ICE ICE BABY\x04\x04\x04"
            .as_bytes()
            .validate_unpad_pkcs7()
            .is_err());
        assert!("ICE ICE BABY\x05\x05\x05\x05"
            .as_bytes()
            .validate_unpad_pkcs7()
            .is_err());
        assert!("ICE ICE BABY\x01\x02\x03\x04"
            .as_bytes()
            .validate_unpad_pkcs7()
            .is_err());
        assert!(vec![16; 16].validate_unpad_pkcs7().is_ok());

        // too short
        assert!(vec![0; 0].validate_unpad_pkcs7().is_err());

        // 0 is not a valid pkcs7 padding byte
        assert!(vec![0; 16].validate_unpad_pkcs7().is_err());

        for byte in 1..=16 {
            // this is ok -- it's (blocksize-byte) data bytes (all same value)
            // + (byte) number of padding bytes (all of which are the same value)
            assert!(vec![byte; 16].validate_unpad_pkcs7().is_ok());
        }
    }
}
