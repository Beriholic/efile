use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use argon2::Argon2;
use rand::rngs::OsRng;
use rand::RngCore;

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let argon = Argon2::default();
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| anyhow!("argon2 error"))?;
    Ok(key)
}

pub fn encrypt_with_name(password: &str, plaintext: &[u8], filename: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("invalid key"))?;
    let mut content_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut content_nonce);
    let mut name_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut name_nonce);
    let ct_content = cipher
        .encrypt(Nonce::from_slice(&content_nonce), plaintext)
        .map_err(|_| anyhow!("encrypt error"))?;
    let ct_name = cipher
        .encrypt(Nonce::from_slice(&name_nonce), filename.as_bytes())
        .map_err(|_| anyhow!("encrypt error"))?;
    let mut out = Vec::new();
    out.extend_from_slice(b"EFIL");
    out.push(2u8);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&content_nonce);
    out.extend_from_slice(&name_nonce);
    let name_len = ct_name.len() as u32;
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(&ct_name);
    out.extend_from_slice(&ct_content);
    Ok((out, ct_name))
}

pub fn decrypt_with_name(password: &str, data: &[u8]) -> Result<(Option<String>, Vec<u8>)> {
    if data.len() < 4 + 1 + 16 + 12 {
        return Err(anyhow!("invalid data"));
    }
    if &data[0..4] != b"EFIL" {
        return Err(anyhow!("invalid header"));
    }
    let ver = data[4];
    if ver == 1u8 {
        let salt = &data[5..21];
        let nonce_bytes = &data[21..33];
        let ct = &data[33..];
        let key = derive_key(password, salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("invalid key"))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let pt = cipher
            .decrypt(nonce, ct)
            .map_err(|_| anyhow!("decrypt error"))?;
        return Ok((None, pt));
    }
    if ver != 2u8 {
        return Err(anyhow!("unsupported version"));
    }
    let salt = &data[5..21];
    let content_nonce = &data[21..33];
    let name_nonce = &data[33..45];
    let name_len_bytes = &data[45..49];
    let name_len = u32::from_le_bytes(name_len_bytes.try_into().unwrap()) as usize;
    if data.len() < 49 + name_len {
        return Err(anyhow!("invalid data"));
    }
    let ct_name = &data[49..49 + name_len];
    let ct_content = &data[49 + name_len..];
    let key = derive_key(password, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("invalid key"))?;
    let name = cipher
        .decrypt(Nonce::from_slice(name_nonce), ct_name)
        .map_err(|_| anyhow!("decrypt error"))?;
    let pt = cipher
        .decrypt(Nonce::from_slice(content_nonce), ct_content)
        .map_err(|_| anyhow!("decrypt error"))?;
    let name_str = String::from_utf8(name).map_err(|_| anyhow!("invalid utf8"))?;
    Ok((Some(name_str), pt))
}
