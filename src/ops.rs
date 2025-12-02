use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::cmp::Reverse;
use walkdir::WalkDir;

use crate::crypto::{decrypt_basename, decrypt_with_name, encrypt_basename, encrypt_with_name};

pub fn process_inputs(inputs: Vec<PathBuf>, password: &str, encrypt: bool) -> Result<()> {
    if inputs.is_empty() {
        return Err(anyhow!("no input provided"));
    }
    let mut targets: Vec<PathBuf> = Vec::new();
    for input in &inputs {
        if input.is_dir() {
            for entry in WalkDir::new(&input).into_iter().filter_map(|e| e.ok()) {
                let p = entry.path().to_path_buf();
                if p.is_file() {
                    if encrypt {
                        if p.extension().and_then(|e| e.to_str()) == Some("enc") {
                            continue;
                        }
                    } else {
                        if p.extension().and_then(|e| e.to_str()) != Some("enc") {
                            continue;
                        }
                    }
                    targets.push(p);
                }
            }
        } else if input.is_file() {
            if encrypt {
                if input.extension().and_then(|e| e.to_str()) != Some("enc") {
                    targets.push(input.to_path_buf());
                }
            } else {
                targets.push(input.to_path_buf());
            }
        } else {
            return Err(anyhow!("invalid path"));
        }
    }

    let pb = ProgressBar::new(targets.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("{bar:40.cyan/blue} {pos}/{len} {percent}%").unwrap(),
    );
    targets.par_iter().try_for_each(|p| -> Result<()> {
        if encrypt {
            encrypt_file(p, password)?;
        } else {
            decrypt_file(p, password)?;
        }
        pb.inc(1);
        Ok(())
    })?;
    pb.finish();
    for input in &inputs {
        if input.is_dir() {
            let mut dirs: Vec<PathBuf> = WalkDir::new(&input)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .map(|e| e.path().to_path_buf())
                .collect();
            if encrypt {
                dirs.sort_by_key(|p| Reverse(p.components().count()));
                for d in dirs {
                    let name = d.file_name().and_then(|s| s.to_str()).unwrap_or("");
                    if name.is_empty() {
                        continue;
                    }
                    let enc_name = encrypt_basename(password, name)?;
                    let new_path = d.parent().unwrap_or(Path::new(".")).join(enc_name);
                    if d != new_path {
                        fs::rename(&d, &new_path)?;
                    }
                }
            } else {
                dirs.sort_by_key(|p| Reverse(p.components().count()));
                for d in dirs {
                    let name = d.file_name().and_then(|s| s.to_str()).unwrap_or("");
                    if name.is_empty() {
                        continue;
                    }
                    if let Ok(dec) = decrypt_basename(password, name) {
                        let new_path = d.parent().unwrap_or(Path::new(".")).join(dec);
                        if d != new_path {
                            fs::rename(&d, &new_path)?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
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
    let out = encrypt_with_name(password, &data, fname)?;
    let parent = path.parent().unwrap_or(Path::new("."));
    let enc_name = encrypt_basename(password, fname)?;
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
        let base = if fname.ends_with(".enc") {
            &fname[..fname.len() - 4]
        } else {
            fname
        };
        match decrypt_basename(password, base) {
            Ok(n) => n,
            Err(_) => base.to_string(),
        }
    };
    let out_path = parent.join(out_name);
    write_atomic_to(&out_path, &pt)?;
    fs::remove_file(path)?;
    Ok(())
}
