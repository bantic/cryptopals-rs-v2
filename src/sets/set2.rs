use crate::{
    aes, base64,
    utils::{self, bytes},
};

const CHALLENGE10_INPUT: &str = include_str!("../files/10.txt");

fn challenge10() -> anyhow::Result<()> {
    let encrypted = base64::from_file_str(CHALLENGE10_INPUT);
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = &bytes::of_len(16, 0);
    let decrypted = aes::decrypt_aes_cbc(&encrypted, iv, key)?;
    println!(
        "✅ Challenge 10: AES CBC Mode\n\t{}",
        utils::truncate(String::from_utf8_lossy(&decrypted).into())
    );
    Ok(())
}

pub fn main() -> anyhow::Result<()> {
    println!("\n========= Set 2 =======\n-----------------------");
    challenge10()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{aes, base64, utils::bytes};
    const CHALLENGE10_EXPECTED: &str = include_str!("../files/funky_music_lyrics.txt");

    use super::CHALLENGE10_INPUT;

    #[test]
    fn test_challenge10() -> anyhow::Result<()> {
        let encrypted = base64::from_file_str(CHALLENGE10_INPUT);
        let key = "YELLOW SUBMARINE".as_bytes();
        let iv = &bytes::of_len(16, 0);
        let binding = aes::decrypt_aes_cbc(&encrypted, iv, key)?;
        let decrypted = String::from_utf8_lossy(&binding);
        assert_eq!(decrypted, CHALLENGE10_EXPECTED);
        Ok(())
    }
}
