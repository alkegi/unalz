use std::io::Cursor;
use std::sync::atomic::{AtomicU32, Ordering};

use unalz::archive::{AlzArchive, CompressionMethod};
use unalz::decompress::{bzip2, deflate, raw};

/// Minimal ALZ archive: one file "t/t.txt" containing "42", DEFLATE compressed.
/// From patool test suite (https://github.com/wummel/patool).
const T_ALZ: &[u8] = &[
    0x41, 0x4c, 0x5a, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x42, 0x4c, 0x5a, 0x01, 0x07, 0x00, 0x20, 0xd8,
    0xb2, 0x8e, 0x41, 0x20, 0x00, 0x02, 0x00, 0x88, 0xb0, 0x24, 0x32, 0x04, 0x00, 0x02, 0x00, 0x74,
    0x2f, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x33, 0x31, 0x02, 0x00, 0x43, 0x4c, 0x5a, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x4c, 0x5a, 0x02,
];

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Per-test unique directory to avoid conflicts with parallel test execution.
fn test_dir() -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("unalz-test-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn open_test_archive() -> (AlzArchive, std::path::PathBuf) {
    let dir = test_dir();
    let path = dir.join("test.alz");
    std::fs::write(&path, T_ALZ).unwrap();
    let archive = AlzArchive::open(path.to_str().unwrap()).unwrap();
    (archive, dir)
}

#[test]
fn parse_archive() {
    let (archive, _dir) = open_test_archive();

    assert_eq!(archive.entries.len(), 1);
    let entry = &archive.entries[0];
    assert_eq!(entry.file_name, "t/t.txt");
    assert_eq!(entry.uncompressed_size, 2);
    assert_eq!(entry.compressed_size, 4);
    assert_eq!(entry.compression_method, CompressionMethod::Deflate);
    assert!(!entry.is_encrypted());
    assert!(!entry.is_directory());
}

#[test]
fn extract_to_dir() {
    let (mut archive, dir) = open_test_archive();
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();

    unalz::extract::extract_all(&mut archive, &out, None, false, true).unwrap();
    assert_eq!(std::fs::read(out.join("t/t.txt")).unwrap(), b"42");
}

#[test]
fn extract_selective() {
    let (mut archive, dir) = open_test_archive();
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();

    let files = vec!["t/t.txt".to_string()];
    unalz::extract::extract_files(&mut archive, &out, &files, None, false, true).unwrap();
    assert_eq!(std::fs::read(out.join("t/t.txt")).unwrap(), b"42");
}

#[test]
fn extract_nonexistent_file_skipped() {
    let (mut archive, dir) = open_test_archive();
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();

    let files = vec!["nonexistent.txt".to_string()];
    unalz::extract::extract_files(&mut archive, &out, &files, None, false, true).unwrap();
    assert!(!out.join("nonexistent.txt").exists());
}

#[test]
fn reject_non_alz() {
    let dir = test_dir();
    let path = dir.join("bad.alz");
    std::fs::write(&path, b"not an alz file").unwrap();
    assert!(AlzArchive::open(path.to_str().unwrap()).is_err());
}

#[test]
fn reject_path_traversal() {
    let (mut archive, dir) = open_test_archive();
    archive.entries[0].file_name = "../etc/passwd".to_string();

    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    assert!(unalz::extract::extract_all(&mut archive, &out, None, false, true).is_err());
}

/// A DEFLATE entry that expands far beyond its declared uncompressed_size must
/// be rejected (decompression-bomb guard), and no partial file left behind.
#[test]
fn reject_decompression_bomb() {
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    // ~2 MB of zeros -> tiny DEFLATE stream.
    let zeros = vec![0u8; 2 * 1024 * 1024];
    let mut comp = Vec::new();
    let mut enc = DeflateEncoder::new(&mut comp, Compression::best());
    enc.write_all(&zeros).unwrap();
    enc.finish().unwrap();

    // Build a minimal ALZ: header + one deflate local file header that LIES,
    // declaring uncompressed_size = 16 while the stream expands to 2 MB.
    let mut a: Vec<u8> = vec![0x41, 0x4c, 0x5a, 0x01, 0x0a, 0x00, 0x00, 0x00]; // "ALZ\x01" + ver/id
    a.extend_from_slice(&[0x42, 0x4c, 0x5a, 0x01]); // "BLZ\x01"
    a.extend_from_slice(&(b"bomb.bin".len() as u16).to_le_bytes());
    a.push(0x20); // attr (archive)
    a.extend_from_slice(&0u32.to_le_bytes()); // time
    a.push(0x80); // descriptor: byte_len = 8
    a.push(0x00); // unknown2
    a.push(0x02); // compression method = deflate
    a.push(0x00); // unknown
    a.extend_from_slice(&0u32.to_le_bytes()); // crc (irrelevant; cap trips first)
    a.extend_from_slice(&(comp.len() as u64).to_le_bytes()); // compressed size
    a.extend_from_slice(&16u64.to_le_bytes()); // uncompressed size (LIE)
    a.extend_from_slice(b"bomb.bin");
    a.extend_from_slice(&comp);
    a.extend_from_slice(&[0x43, 0x4c, 0x5a, 0x02]); // "CLZ\x02" end-of-central-dir
    a.extend_from_slice(&[0u8; 16]); // tail

    let mut archive = AlzArchive::from_bytes(a).unwrap();
    let dir = test_dir();
    let result = unalz::extract::extract_all(&mut archive, &dir, None, false, true);
    assert!(result.is_err(), "bomb should be rejected");
    assert!(
        !dir.join("bomb.bin").exists(),
        "partial bomb output must be cleaned up"
    );
}

#[test]
fn raw_decompress() {
    let data = b"hello world";
    let mut reader = Cursor::new(data.as_slice());
    let mut output = Vec::new();

    let crc =
        raw::extract_raw(&mut reader, &mut output, data.len() as u64, u64::MAX, None).unwrap();

    assert_eq!(&output, data);
    let mut h = crc32fast::Hasher::new();
    h.update(data);
    assert_eq!(crc, h.finalize());
}

#[test]
fn deflate_decompress() {
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    let input = b"hello";
    let mut compressed = Vec::new();
    let mut enc = DeflateEncoder::new(&mut compressed, Compression::default());
    enc.write_all(input).unwrap();
    enc.finish().unwrap();

    let mut reader = Cursor::new(compressed.as_slice());
    let mut output = Vec::new();
    let crc = deflate::extract_deflate(
        &mut reader,
        &mut output,
        compressed.len() as u64,
        u64::MAX,
        None,
    )
    .unwrap();

    assert_eq!(&output, input);
    let mut h = crc32fast::Hasher::new();
    h.update(input);
    assert_eq!(crc, h.finalize());
}

#[test]
fn bzip2_decompress() {
    // ALZ-format bzip2 data for "hello world" (generated from standard bzip2
    // by stripping stream header, replacing block/EOS magic with DLZ\x01/\x02,
    // removing per-block CRC and randomised bit).
    let alz_bz2: &[u8] = &[
        0x44, 0x4c, 0x5a, 0x01, 0x00, 0x00, 0x03, 0x23, 0x00, 0x80, 0x00, 0x0c, 0x89, 0x21, 0x00,
        0x40, 0x00, 0x44, 0x06, 0x69, 0x08, 0x60, 0x43, 0x6d, 0x02, 0xa8, 0x4f, 0x44, 0x4c, 0x5a,
        0x02,
    ];

    let mut reader = Cursor::new(alz_bz2);
    let mut output = Vec::new();
    let crc = bzip2::extract_bzip2(
        &mut reader,
        &mut output,
        alz_bz2.len() as u64,
        u64::MAX,
        None,
    )
    .unwrap();

    assert_eq!(&output, b"hello world");
    let mut h = crc32fast::Hasher::new();
    h.update(b"hello world");
    assert_eq!(crc, h.finalize());
}
