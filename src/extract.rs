//! Entry extraction: path safety, decompression dispatch, and CRC verification.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path};

use crate::archive::{AlzArchive, AlzFileEntry, CompressionMethod};
use crate::crypto::ZipCrypto;
use crate::decompress::{bzip2, deflate, raw};
use crate::dostime::dos_datetime_to_systime;
use crate::encoding::password_to_cp949;
use crate::error::{AlzError, AlzResult};

/// Upper bound on a decompressed symlink target. A path longer than this is
/// invalid anyway, and the cap stops an entry with a forged huge
/// uncompressed_size from ballooning the in-memory target buffer.
const SYMLINK_TARGET_MAX: u64 = 65536;

/// Reject paths that could escape the destination directory: parent-dir
/// (`..`) components, absolute roots, or Windows drive prefixes. Backslashes
/// are normalized to `/` by callers before this check.
fn has_unsafe_components(path: &Path) -> bool {
    path.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    })
}

/// Extract a single file entry from the archive.
pub fn extract_entry(
    archive: &mut AlzArchive,
    entry: &AlzFileEntry,
    dest_dir: &Path,
    password: Option<&str>,
    pipe_mode: bool,
) -> AlzResult<()> {
    let mut crypto = if entry.is_encrypted() {
        let pwd = password.ok_or(AlzError::PasswordNotSet)?;
        let enc_chk = entry.enc_check.as_ref().ok_or(AlzError::PasswordNotSet)?;
        // ZIP keys are derived from the CP949 bytes of the password.
        let pwd_bytes = password_to_cp949(pwd);
        let mut c = ZipCrypto::new(&pwd_bytes);
        if !c.check_header(
            enc_chk,
            entry.file_crc,
            entry.file_time_date,
            entry.has_data_descriptor(),
        ) {
            return Err(AlzError::InvalidPassword);
        }
        // Re-initialize for actual decryption.
        let mut c = ZipCrypto::new(&pwd_bytes);
        // Re-process the encryption header to advance key state.
        let mut hdr_copy = *enc_chk;
        c.decrypt(&mut hdr_copy);
        Some(c)
    } else {
        None
    };

    let file_name = entry.file_name.replace('\\', "/");

    // Security: reject parent-dir (`..`) traversal and absolute paths up
    // front, before touching the filesystem.
    if has_unsafe_components(Path::new(&file_name)) {
        return Err(AlzError::PathTraversal(file_name));
    }

    let dest_path = dest_dir.join(&file_name);

    // Defense in depth: confirm the resolved path stays inside dest_dir,
    // catching escapes via a symlinked destination directory.
    if !pipe_mode {
        let canonical_dest = fs::canonicalize(dest_dir)?;
        // dest_path may not exist yet; resolve via its parent directory.
        let resolved = if let Some(parent) = dest_path.parent() {
            fs::create_dir_all(parent)?;
            fs::canonicalize(parent)?.join(dest_path.file_name().unwrap_or_default())
        } else {
            dest_path.clone()
        };
        if !resolved.starts_with(&canonical_dest) {
            return Err(AlzError::PathTraversal(file_name));
        }
    }

    if entry.is_directory() {
        if !pipe_mode {
            fs::create_dir_all(&dest_path)?;
        }
        return Ok(());
    }

    if entry.is_symlink() {
        archive.reader.seek(SeekFrom::Start(entry.data_pos))?;
        let mut limited = (&mut archive.reader).take(entry.compressed_size);
        let mut buf = Vec::new();
        let crc = decompress_to(
            &mut limited,
            &mut buf,
            entry,
            SYMLINK_TARGET_MAX,
            crypto.as_mut(),
        )?;
        if crc != entry.file_crc {
            return Err(AlzError::InvalidFileCrc {
                expected: entry.file_crc,
                got: crc,
            });
        }
        let target = String::from_utf8_lossy(&buf);
        if pipe_mode {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            out.write_all(target.as_bytes())
                .map_err(AlzError::CantOpenDestFile)?;
        } else {
            let normalized = target.replace('\\', "/");
            if has_unsafe_components(Path::new(&normalized)) {
                return Err(AlzError::PathTraversal(target.into_owned()));
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink(target.as_ref(), &dest_path)?;
            #[cfg(not(unix))]
            fs::write(&dest_path, target.as_bytes())?;
        }
        return Ok(());
    }

    archive.reader.seek(SeekFrom::Start(entry.data_pos))?;
    let mut limited = (&mut archive.reader).take(entry.compressed_size);

    let crc = if pipe_mode {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        decompress_to(
            &mut limited,
            &mut out,
            entry,
            entry.uncompressed_size,
            crypto.as_mut(),
        )?
    } else {
        let mut file = fs::File::create(&dest_path).map_err(AlzError::CantOpenDestFile)?;
        // On any decompression failure, remove the partial output file so a
        // rejected (e.g. bomb-capped or corrupt) entry leaves nothing behind.
        let crc = match decompress_to(
            &mut limited,
            &mut file,
            entry,
            entry.uncompressed_size,
            crypto.as_mut(),
        ) {
            Ok(crc) => crc,
            Err(e) => {
                drop(file);
                let _ = fs::remove_file(&dest_path);
                return Err(e);
            }
        };
        file.flush().map_err(AlzError::CantOpenDestFile)?;
        if let Some(systime) = dos_datetime_to_systime(entry.file_time_date) {
            let _ = file.set_modified(systime);
        }
        drop(file);

        crc
    };

    if crc != entry.file_crc {
        if !pipe_mode {
            let _ = fs::remove_file(&dest_path);
        }
        return Err(AlzError::InvalidFileCrc {
            expected: entry.file_crc,
            got: crc,
        });
    }

    Ok(())
}

fn decompress_to<R: io::Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    entry: &AlzFileEntry,
    max_output: u64,
    crypto: Option<&mut ZipCrypto>,
) -> AlzResult<u32> {
    match entry.compression_method {
        CompressionMethod::Store => {
            raw::extract_raw(reader, writer, entry.compressed_size, max_output, crypto)
        }
        CompressionMethod::Deflate => {
            deflate::extract_deflate(reader, writer, entry.compressed_size, max_output, crypto)
        }
        CompressionMethod::Bzip2 => {
            bzip2::extract_bzip2(reader, writer, entry.compressed_size, max_output, crypto)
        }
        CompressionMethod::Unknown(n) => Err(AlzError::UnknownCompressionMethod(n)),
    }
}

/// Extract all entries from the archive.
pub fn extract_all(
    archive: &mut AlzArchive,
    dest_dir: &Path,
    password: Option<&str>,
    pipe_mode: bool,
    quiet: bool,
) -> AlzResult<()> {
    let entries: Vec<AlzFileEntry> = archive.entries.clone();
    for entry in &entries {
        if !quiet && !pipe_mode {
            eprint!(
                "\nextracting : {} ({}bytes) ",
                entry.file_name, entry.uncompressed_size
            );
        }
        extract_entry(archive, entry, dest_dir, password, pipe_mode)?;
        if !quiet && !pipe_mode {
            eprint!(".. ok");
        }
    }
    Ok(())
}

/// Extract specific files by name.
pub fn extract_files(
    archive: &mut AlzArchive,
    dest_dir: &Path,
    file_names: &[String],
    password: Option<&str>,
    pipe_mode: bool,
    quiet: bool,
) -> AlzResult<()> {
    let entries: Vec<AlzFileEntry> = archive.entries.clone();
    for name in file_names {
        if let Some(entry) = entries.iter().find(|e| e.file_name == *name) {
            if !quiet && !pipe_mode {
                eprint!(
                    "\nextracting : {} ({}bytes) ",
                    entry.file_name, entry.uncompressed_size
                );
            }
            extract_entry(archive, entry, dest_dir, password, pipe_mode)?;
            if !quiet && !pipe_mode {
                eprint!(".. ok");
            }
        } else if !quiet && !pipe_mode {
            eprintln!("\nfilename not matched : {name}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_components_are_rejected() {
        // Callers normalize '\\' to '/' before this check.
        for p in ["../etc", "a/../../b", "..", "a/..", "/etc/passwd"] {
            assert!(has_unsafe_components(Path::new(p)), "should reject {p}");
        }
        for p in ["a/b/c.txt", "한글.txt", "deep/dir/file", "a.b/c"] {
            assert!(!has_unsafe_components(Path::new(p)), "should allow {p}");
        }
    }
}
