use crate::{aes::break_cbc_padding_oracle, base64::DecodeBase64, oracle::CbcPaddingOracle};

fn challenge17() -> anyhow::Result<()> {
    println!("Challenge 17: Break CBC with a padding oracle");
    let b64_plaintexts = include_str!("../files/cbc-plaintexts-b64.txt");
    for line in b64_plaintexts.lines() {
        let plaintext = line.trim().decode_base64();
        let oracle = CbcPaddingOracle::new(plaintext)?;
        let result = break_cbc_padding_oracle(&oracle)?;

        let emoji = if oracle.verify(&result) { "✅" } else { "❌" };
        println!("{emoji} {}", String::from_utf8(result)?);
    }
    Ok(())
}

pub fn main() -> anyhow::Result<()> {
    println!("\n========= Set 3 =======\n-----------------------");
    challenge17()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{aes::break_cbc_padding_oracle, base64::DecodeBase64, oracle::CbcPaddingOracle};

    #[test]
    fn test_challenge17() -> anyhow::Result<()> {
        let b64_plaintexts = include_str!("../files/cbc-plaintexts-b64.txt");
        for line in b64_plaintexts.lines() {
            let plaintext = line.trim().decode_base64();
            let oracle = CbcPaddingOracle::new(plaintext)?;
            let result = break_cbc_padding_oracle(&oracle)?;
            assert!(oracle.verify(&result));
        }
        Ok(())
    }
}
