use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::Cursor;
use walkdir::WalkDir;
use zip::read::ZipArchive;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::crypto::{decrypt_basename, decrypt_with_name, encrypt_basename, encrypt_with_name};

pub fn process_inputs(inputs: Vec<PathBuf>, password: &str, encrypt: bool) -> Result<()> {
    if inputs.is_empty() {
        return Err(anyhow!("no input provided"));
    }
    let mut targets: Vec<PathBuf> = Vec::new();
    for input in &inputs {
        if encrypt {
            if input.is_dir() {
                targets.push(input.to_path_buf());
            } else if input.is_file() {
                if input.extension().and_then(|e| e.to_str()) != Some("enc") {
                    targets.push(input.to_path_buf());
                }
            } else {
                return Err(anyhow!("invalid path"));
            }
        } else {
            if input.is_dir() {
                for entry in WalkDir::new(&input).into_iter().filter_map(|e| e.ok()) {
                    let p = entry.path().to_path_buf();
                    if p.is_file() {
                        if p.extension().and_then(|e| e.to_str()) == Some("enc") {
                            targets.push(p);
                        }
                    }
                }
            } else if input.is_file() {
                targets.push(input.to_path_buf());
            } else {
                return Err(anyhow!("invalid path"));
            }
        }
    }

    let pb = ProgressBar::new(targets.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("{bar:40.cyan/blue} {pos}/{len} {percent}%").unwrap(),
    );
    for p in &targets {
        if encrypt {
            if p.is_dir() {
                encrypt_directory(p, password)?;
            } else {
                encrypt_file(p, password)?;
            }
        } else {
            decrypt_file(p, password)?;
        }
        pb.inc(1);
    }
    pb.finish();
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
    if out_name.ends_with(".zip") {
        println!("正在解压缩: {}", out_name);
        let mut cursor = Cursor::new(pt);
        let mut archive = ZipArchive::new(&mut cursor).map_err(|_| anyhow!("invalid zip"))?;
        let count = archive.len() as u64;
        let pb = ProgressBar::new(count);
        pb.set_style(
            ProgressStyle::with_template("{bar:40.green/blue} {pos}/{len} {percent}%").unwrap(),
        );
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|_| anyhow!("invalid zip"))?;
            let file_name = file.name().to_string();
            let out_path = parent.join(&file_name);
            if file.is_dir() {
                fs::create_dir_all(&out_path)?;
            } else {
                if let Some(p) = out_path.parent() {
                    fs::create_dir_all(p)?;
                }
                let mut outfile = fs::File::create(&out_path)?;
                std::io::copy(&mut file, &mut outfile)?;
            }
            pb.inc(1);
        }
        pb.finish();
        fs::remove_file(path)?;
        Ok(())
    } else {
        let out_path = parent.join(out_name);
        write_atomic_to(&out_path, &pt)?;
        fs::remove_file(path)?;
        Ok(())
    }
}

pub fn encrypt_directory(path: &Path, password: &str) -> Result<()> {
    let root_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("invalid dir name"))?;
    println!("正在压缩目录: {}", root_name);
    let count = WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .count() as u64;
    let pb = ProgressBar::new(count);
    pb.set_style(
        ProgressStyle::with_template("{bar:40.cyan/blue} {pos}/{len} {percent}%").unwrap(),
    );
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        let p = entry.path().to_path_buf();
        if p.is_file() {
            let rel = p
                .strip_prefix(path)
                .map_err(|_| anyhow!("strip prefix error"))?;
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            let name_in_zip = format!("{}/{}", root_name, rel_str);
            writer.start_file(name_in_zip, options)?;
            let mut f = fs::File::open(&p)?;
            let mut data = Vec::new();
            f.read_to_end(&mut data)?;
            writer.write_all(&data)?;
            pb.inc(1);
        }
    }
    pb.finish();
    let cursor = writer.finish()?;
    let zip_bytes = cursor.into_inner();
    let zip_name = format!("{}.zip", root_name);
    let out = encrypt_with_name(password, &zip_bytes, &zip_name)?;
    let parent = path.parent().unwrap_or(Path::new("."));
    let enc_base = encrypt_basename(password, &zip_name)?;
    let out_path = parent.join(format!("{}{}", enc_base, ".enc"));
    write_atomic_to(&out_path, &out)?;
    fs::remove_dir_all(path)?;
    Ok(())
}
