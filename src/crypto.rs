use age::secrecy::SecretString;
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn encrypt_with_name(password: &str, plaintext: &[u8], filename: &str) -> Result<Vec<u8>> {
    let passphrase = SecretString::from(password.to_owned());
    let recipient = age::scrypt::Recipient::new(passphrase.clone());

    let name_bytes = filename.as_bytes();
    let mut combined = Vec::with_capacity(4 + name_bytes.len() + plaintext.len());
    combined.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
    combined.extend_from_slice(name_bytes);
    combined.extend_from_slice(plaintext);

    let encrypted = age::encrypt(&recipient, &combined).map_err(|_| anyhow!("encrypt error"))?;
    Ok(encrypted)
}

pub fn decrypt_with_name(password: &str, data: &[u8]) -> Result<(Option<String>, Vec<u8>)> {
    let passphrase = SecretString::from(password.to_owned());
    let identity = age::scrypt::Identity::new(passphrase);

    let decrypted = age::decrypt(&identity, data).map_err(|_| anyhow!("decrypt error"))?;

    if decrypted.len() < 4 {
        return Err(anyhow!("invalid data"));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&decrypted[0..4]);
    let name_len = u32::from_be_bytes(len_bytes) as usize;
    if decrypted.len() < 4 + name_len {
        return Err(anyhow!("invalid data"));
    }
    let name = String::from_utf8(decrypted[4..4 + name_len].to_vec())
        .map_err(|_| anyhow!("invalid utf8"))?;
    let content = decrypted[4 + name_len..].to_vec();
    Ok((Some(name), content))
}

pub fn encrypt_basename(password: &str, name: &str) -> Result<String> {
    let key = Sha256::digest(password.as_bytes());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut buf = name.as_bytes().to_vec();
    let mut cipher = ChaCha20::new((&key).into(), (&nonce).into());
    cipher.apply_keystream(&mut buf);
    let mut out = Vec::with_capacity(12 + buf.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(URL_SAFE_NO_PAD.encode(out))
}

pub fn decrypt_basename(password: &str, enc_name: &str) -> Result<String> {
    let raw = URL_SAFE_NO_PAD
        .decode(enc_name.as_bytes())
        .map_err(|_| anyhow!("invalid name"))?;
    if raw.len() < 12 {
        return Err(anyhow!("invalid name"));
    }
    let key = Sha256::digest(password.as_bytes());
    let nonce = &raw[..12];
    let mut buf = raw[12..].to_vec();
    let mut cipher = ChaCha20::new((&key).into(), nonce.into());
    cipher.apply_keystream(&mut buf);
    let name = String::from_utf8(buf).map_err(|_| anyhow!("invalid utf8"))?;
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_passphrase_encryption() {
        let password = "test-passphrase";
        let plaintext = b"hello world";
        let filename = "hello.txt";
        let encrypted = encrypt_with_name(password, plaintext, filename).unwrap();
        let (maybe_name, decrypted) = decrypt_with_name(password, &encrypted).unwrap();
        assert_eq!(maybe_name.as_deref(), Some(filename));
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_binary_encryption() {
        let password = "test-passphrase";
        let filename = "bin.dat";
        let plaintext: Vec<u8> = (0u8..=255u8).collect();
        let encrypted = encrypt_with_name(password, &plaintext, filename).unwrap();
        let (maybe_name, decrypted) = decrypt_with_name(password, &encrypted).unwrap();
        assert_eq!(maybe_name.as_deref(), Some(filename));
        assert_eq!(decrypted, plaintext);
    }
}
