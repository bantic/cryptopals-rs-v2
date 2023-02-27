use std::collections::HashMap;

use rand::Rng;

use crate::{aes, utils::bytes};

pub struct Oracle<T> {
    pub ciphertext: Vec<u8>,
    mode: T,
}

impl Oracle<aes::Mode> {
    pub fn verify(&self, mode: &aes::Mode) -> bool {
        &self.mode == mode
    }
}

pub fn guess(oracle: &Oracle<aes::Mode>) -> aes::Mode {
    match aes::detect_aes_128_ecb(&oracle.ciphertext) {
        true => aes::Mode::ECB,
        false => aes::Mode::CBC,
    }
}

pub fn encrypt(plaintext: &[u8]) -> anyhow::Result<Oracle<aes::Mode>> {
    let block_size = 16;
    let key = &bytes::rand_of_len(block_size);
    let mut data = vec![];

    let mut rng = rand::thread_rng();
    let prepend_len = rng.gen_range(5..=15);
    let append_len = rng.gen_range(5..=15);
    data.extend(bytes::rand_of_len(prepend_len));
    data.extend(plaintext);
    data.extend(bytes::rand_of_len(append_len));

    let mode;
    let ciphertext = if rand::random() {
        mode = aes::Mode::ECB;
        aes::encrypt_aes_ecb(&data, key)?
    } else {
        mode = aes::Mode::CBC;
        let iv = bytes::rand_of_len(block_size);
        aes::encrypt_aes_cbc(&data, &iv, key)?
    };
    Ok(Oracle { ciphertext, mode })
}

pub trait EncryptingOracle {
    fn encrypt(&self, padding: &[u8]) -> anyhow::Result<Vec<u8>>;
}

pub struct PaddingOracle {
    key: Vec<u8>,
    secret: Vec<u8>,
}

impl PaddingOracle {
    pub fn new(secret: Vec<u8>) -> Self {
        let blocksize = 16;
        let key = bytes::rand_of_len(blocksize);
        PaddingOracle { key, secret }
    }
    pub fn encrypt(&self, padding: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut plaintext = vec![];
        plaintext.extend(padding);
        plaintext.extend(&self.secret);
        aes::encrypt_aes_ecb(&plaintext, &self.key)
    }
    pub fn verify(&self, plaintext: &[u8]) -> bool {
        self.secret == plaintext
    }
}

impl EncryptingOracle for PaddingOracle {
    fn encrypt(&self, padding: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.encrypt(padding)
    }
}

impl EncryptingOracle for PrefixPaddingOracle {
    fn encrypt(&self, padding: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.encrypt(padding)
    }
}

impl EncryptingOracle for ProfileOracle {
    fn encrypt(&self, padding: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.encrypt(padding)
    }
}

pub struct PrefixPaddingOracle {
    key: Vec<u8>,
    prefix: Vec<u8>,
    secret: Vec<u8>,
}

impl PrefixPaddingOracle {
    pub fn new(secret: Vec<u8>) -> Self {
        let blocksize = 16;
        let key = bytes::rand_of_len(blocksize);
        let mut rng = rand::thread_rng();
        let prefix_len = rng.gen_range(5..=40);
        let prefix = bytes::rand_of_len(prefix_len);
        PrefixPaddingOracle {
            key,
            prefix,
            secret,
        }
    }
    pub fn encrypt(&self, bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut plaintext = vec![];
        plaintext.extend(&self.prefix);
        plaintext.extend(bytes);
        plaintext.extend(&self.secret);
        aes::encrypt_aes_ecb(&plaintext, &self.key)
    }

    pub fn verify(&self, plaintext: &[u8]) -> bool {
        self.secret == plaintext
    }
}

pub struct ProfileOracle {
    key: Vec<u8>,
}

impl ProfileOracle {
    pub fn new() -> Self {
        Self {
            key: bytes::rand_of_len(16),
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let email = String::from_utf8(data.to_vec())?;
        aes::encrypt_aes_ecb(Self::profile_for(&email).as_bytes(), &self.key)
    }

    pub fn verify(&self, ciphertext: &[u8]) -> anyhow::Result<bool> {
        let profile = self.decrypt(ciphertext)?;
        if let Some(v) = profile.get("role") {
            Ok(v == "admin")
        } else {
            Ok(false)
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<HashMap<String, String>> {
        let decrypted = aes::decrypt_aes_ecb(ciphertext, &self.key)?;
        Ok(Self::kvparse(&String::from_utf8_lossy(&decrypted)))
    }

    fn kvparse(s: &str) -> HashMap<String, String> {
        s.split('&')
            .map(|kv| {
                let mut kv = kv.split('=');
                (kv.next().unwrap().into(), kv.next().unwrap().into())
            })
            .collect()
    }

    fn profile_for(email: &str) -> String {
        let email = email.replace('=', "");
        let email = email.replace('&', "");
        format!("email={email}&uid=10&role=user")
    }
}

impl Default for ProfileOracle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::oracle::ProfileOracle;
    use std::collections::HashMap;

    #[test]
    fn test_kvparse() {
        let parsed = ProfileOracle::kvparse("foo=bar");
        assert_eq!(parsed, HashMap::from([("foo".into(), "bar".into())]));

        let parsed = ProfileOracle::kvparse("foo=bar&baz=qux");
        assert_eq!(
            parsed,
            HashMap::from([("foo".into(), "bar".into()), ("baz".into(), "qux".into())])
        );
    }
}
