use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use walkdir::WalkDir;

use crate::crypto::{decrypt_with_name, encrypt_with_name};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

pub fn process_inputs(inputs: Vec<PathBuf>, password: &str, encrypt: bool) -> Result<()> {
    if inputs.is_empty() {
        return Err(anyhow!("no input provided"));
    }
    for input in inputs {
        if input.is_dir() {
            for entry in WalkDir::new(&input).into_iter().filter_map(|e| e.ok()) {
                let p = entry.path().to_path_buf();
                if p.is_file() {
                    if encrypt {
                        if has_efile_header(&p)? {
                            continue;
                        }
                        encrypt_file(&p, password)?;
                    } else {
                        if p.extension().and_then(|e| e.to_str()) != Some("enc") {
                            continue;
                        }
                        decrypt_file(&p, password)?;
                    }
                }
            }
        } else if input.is_file() {
            if encrypt {
                encrypt_file(&input, password)?;
            } else {
                decrypt_file(&input, password)?;
            }
        } else {
            return Err(anyhow!("invalid path"));
        }
    }
    Ok(())
}

fn has_efile_header(path: &Path) -> Result<bool> {
    let mut buf = [0u8; 4];
    let mut f = fs::File::open(path)?;
    let n = f.read(&mut buf)?;
    if n < 4 {
        return Ok(false);
    }
    Ok(&buf == b"EFIL")
}

fn write_atomic_to(target: &Path, data: &[u8]) -> Result<()> {
    let tmp = PathBuf::from(format!("{}{}", target.display(), ".tmp_efile"));
    {
        let mut f = fs::File::create(&tmp)?;
        use std::io::Write;
        f.write_all(data)?;
    }
    fs::rename(&tmp, target)?;
    Ok(())
}

pub fn encrypt_file(path: &Path, password: &str) -> Result<()> {
    let mut data = Vec::new();
    fs::File::open(path)?.read_to_end(&mut data)?;
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("invalid file name"))?;
    let (out, ct_name) = encrypt_with_name(password, &data, fname)?;
    let enc_name = URL_SAFE_NO_PAD.encode(ct_name);
    let parent = path.parent().unwrap_or(Path::new("."));
    let out_path = parent.join(format!("{}{}", enc_name, ".enc"));
    write_atomic_to(&out_path, &out)?;
    fs::remove_file(path)?;
    Ok(())
}

pub fn decrypt_file(path: &Path, password: &str) -> Result<()> {
    let mut data = Vec::new();
    fs::File::open(path)?.read_to_end(&mut data)?;
    let (maybe_name, pt) = match decrypt_with_name(password, &data) {
        Ok(v) => v,
        Err(_) => return Err(anyhow!("decrypt error")),
    };
    let parent = path.parent().unwrap_or(Path::new("."));
    let out_name = if let Some(n) = maybe_name {
        n
    } else {
        let fname = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow!("invalid file name"))?;
        if fname.ends_with(".enc") {
            fname[..fname.len() - 4].to_string()
        } else {
            fname.to_string()
        }
    };
    let out_path = parent.join(out_name);
    write_atomic_to(&out_path, &pt)?;
    fs::remove_file(path)?;
    Ok(())
}
