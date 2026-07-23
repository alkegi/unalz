//! Regression tests that extract the real ALZ archives under tests/data/.

use std::path::{Path, PathBuf};

use unalz::archive::{AlzArchive, CompressionMethod};

/// (name, length, CRC-32) of the original files the sample archives contain.
const SOURCE: &[(&str, u64, u32)] = &[
    ("binary.bin", 1024, 0xb70b4c26),
    ("empty.txt", 0, 0x00000000),
    ("euckr_content.txt", 71, 0x3e3e0f3f),
    ("hello.txt", 131, 0x1b239eb9),
    ("large.txt", 131364, 0xfe5598ec),
    ("repeated.txt", 720, 0x33ab076a),
    ("뷁테스트.txt", 72, 0x64205eb3),
    ("한글파일.txt", 56, 0xf223d6ec),
    ("subdir/inner.txt", 28, 0xda872f18),
    ("subdir/nested/deep.txt", 20, 0xaab59c3d),
];

fn verify(dir: &Path, name: &str) {
    let (_, len, crc) = SOURCE.iter().find(|(n, ..)| *n == name).unwrap();
    let data = std::fs::read(dir.join(name)).unwrap();
    assert_eq!(data.len() as u64, *len, "{name}: wrong length");
    assert_eq!(crc32fast::hash(&data), *crc, "{name}: wrong CRC");
}

fn alz(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    assert!(path.is_file(), "test archive missing: {}", path.display());
    path.to_str().unwrap().to_string()
}

fn extract_to(path: &str, password: Option<&str>, tag: &str) -> PathBuf {
    let mut archive = AlzArchive::open(path).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "unalz-{}-{}",
        Path::new(path).file_stem().unwrap().to_str().unwrap(),
        tag
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    unalz::extract::extract_all(&mut archive, &dir, password, false, true).unwrap();
    dir
}

macro_rules! extract {
    ($path:expr, $pwd:expr) => {
        extract_to($path, $pwd, concat!(module_path!(), "::", line!()))
    };
}

// --- Store ---

#[test]
fn store_list() {
    let path = alz("store.alz");
    let archive = AlzArchive::open(&path).unwrap();
    assert_eq!(archive.entries.len(), 10);
    for entry in &archive.entries {
        assert_eq!(entry.compression_method, CompressionMethod::Store);
    }
}

#[test]
fn store_extract() {
    let path = alz("store.alz");
    let dir = extract!(&path, None);
    for (name, ..) in SOURCE {
        verify(&dir, name);
    }
}

// --- Deflate (normal) ---

#[test]
fn deflate_normal_list() {
    let path = alz("normal.alz");
    let archive = AlzArchive::open(&path).unwrap();
    assert_eq!(archive.entries.len(), 10);
    // empty.txt is Store, rest are Deflate
    let deflate_count = archive
        .entries
        .iter()
        .filter(|e| e.compression_method == CompressionMethod::Deflate)
        .count();
    assert!(deflate_count >= 9);
}

#[test]
fn deflate_normal_extract() {
    let path = alz("normal.alz");
    let dir = extract!(&path, None);
    for (name, ..) in SOURCE {
        verify(&dir, name);
    }
}

// --- Deflate (low) ---

#[test]
fn deflate_low_extract() {
    let path = alz("low.alz");
    let dir = extract!(&path, None);
    for (name, ..) in SOURCE {
        verify(&dir, name);
    }
}

// --- Encrypted (zip2.0) ---

#[test]
fn encrypted_list() {
    let path = alz("zip20.alz");
    let archive = AlzArchive::open(&path).unwrap();
    assert!(archive.is_encrypted);
    let encrypted_count = archive.entries.iter().filter(|e| e.is_encrypted()).count();
    // empty.txt is not encrypted (0 bytes), rest are
    assert!(encrypted_count >= 9);
}

#[test]
fn encrypted_extract() {
    let path = alz("zip20.alz");
    let dir = extract!(&path, Some("test1234"));
    for (name, ..) in SOURCE {
        verify(&dir, name);
    }
}

#[test]
fn encrypted_wrong_password() {
    let path = alz("zip20.alz");
    let mut archive = AlzArchive::open(&path).unwrap();
    let dir = std::env::temp_dir().join("unalz-wrongpwd");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let result = unalz::extract::extract_all(&mut archive, &dir, Some("wrong"), false, true);
    assert!(result.is_err());
}

// --- Split (multi-volume) ---

#[test]
fn split_list() {
    let path = alz("split.alz");
    let archive = AlzArchive::open(&path).unwrap();
    assert_eq!(archive.entries.len(), 10);
    // large.txt should be 10MB in split archive
    let large = archive
        .entries
        .iter()
        .find(|e| e.file_name == "large.txt")
        .unwrap();
    assert_eq!(large.uncompressed_size, 10485774);
}

#[test]
fn split_extract() {
    let path = alz("split.alz");
    let dir = extract!(&path, None);
    // split.alz carries the 10 MB variant of large.txt, not the 131 KB one in
    // the other archives; verify it directly.
    for (name, ..) in SOURCE.iter().filter(|(n, ..)| *n != "large.txt") {
        verify(&dir, name);
    }
    let large = std::fs::read(dir.join("large.txt")).unwrap();
    assert_eq!(large.len() as u64, 10_485_774);
    assert_eq!(crc32fast::hash(&large), 0xdee4_d582);
}

// --- Edge cases ---

#[test]
fn empty_file() {
    let path = alz("store.alz");
    let dir = extract!(&path, None);
    let empty = std::fs::read(dir.join("empty.txt")).unwrap();
    assert!(empty.is_empty());
}

#[test]
fn cp949_extended_filename() {
    let path = alz("store.alz");
    let archive = AlzArchive::open(&path).unwrap();
    // 뷁 is a CP949-only character not in EUC-KR
    assert!(archive.entries.iter().any(|e| e.file_name.contains("뷁")));
}

#[test]
fn nested_directories() {
    let path = alz("store.alz");
    let dir = extract!(&path, None);
    assert!(dir.join("subdir/nested/deep.txt").exists());
}
