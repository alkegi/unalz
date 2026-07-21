//! Regression test for multi-block ALZ bzip2 extraction.
//!
//! ALZ bzip2 files larger than one bzip2 block (~900 KB uncompressed) span
//! multiple blocks. There is no real multi-block ALZ archive in tests/data, so
//! this test synthesizes one: it compresses data with the standard `bzip2`
//! crate, converts that standard stream into ALZ bzip2 framing (the inverse of
//! what the extractor reconstructs), and checks the extractor round-trips it
//! byte-for-byte — including a case whose compressed payload coincidentally
//! contains a false "DLZ" marker.

use std::io::Write;

use unalz::decompress::bzip2::extract_bzip2;

const BZ_BLOCK_MAGIC: u64 = 0x314159265359; // 48-bit
const BZ_EOS_MAGIC: u64 = 0x177245385090; // 48-bit

struct BitReader<'a> {
    data: &'a [u8],
    bit: usize,
}
impl<'a> BitReader<'a> {
    fn new(d: &'a [u8]) -> Self {
        Self { data: d, bit: 0 }
    }
    fn remaining(&self) -> usize {
        self.data.len() * 8 - self.bit
    }
    fn read1(&mut self) -> u8 {
        let b = (self.data[self.bit / 8] >> (7 - (self.bit % 8))) & 1;
        self.bit += 1;
        b
    }
    fn read(&mut self, n: usize) -> u64 {
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 1) | self.read1() as u64;
        }
        v
    }
    fn peek(&self, n: usize) -> u64 {
        let mut v = 0u64;
        for bit in self.bit..self.bit + n {
            v = (v << 1) | ((self.data[bit / 8] >> (7 - (bit % 8))) & 1) as u64;
        }
        v
    }
}
struct BitWriter {
    data: Vec<u8>,
    cur: u8,
    bit: u8,
}
impl BitWriter {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            cur: 0,
            bit: 0,
        }
    }
    fn write(&mut self, val: u64, n: usize) {
        for i in (0..n).rev() {
            let b = ((val >> i) & 1) as u8;
            self.cur |= b << (7 - self.bit);
            self.bit += 1;
            if self.bit == 8 {
                self.data.push(self.cur);
                self.cur = 0;
                self.bit = 0;
            }
        }
    }
    fn flush(mut self) -> Vec<u8> {
        if self.bit > 0 {
            self.data.push(self.cur);
        }
        self.data
    }
}

/// standard bzip2 stream -> ALZ bzip2 framing.
fn std_to_alz(std: &[u8]) -> Vec<u8> {
    let mut r = BitReader::new(std);
    assert_eq!(r.read(24), 0x425a68, "not a BZh stream"); // "BZh"
    let _level = r.read(8);
    let mut w = BitWriter::new();
    loop {
        let magic = r.read(48);
        if magic == BZ_EOS_MAGIC {
            w.write(0x444C5A02, 32); // DLZ\x02
            break;
        }
        assert_eq!(magic, BZ_BLOCK_MAGIC, "expected block magic");
        let _crc = r.read(32);
        assert_eq!(r.read1(), 0, "randomised blocks unsupported");
        w.write(0x444C5A01, 32); // DLZ\x01
        loop {
            if r.remaining() < 48 {
                while r.remaining() > 0 {
                    let b = r.read1();
                    w.write(b as u64, 1);
                }
                return w.flush();
            }
            let p = r.peek(48);
            if p == BZ_BLOCK_MAGIC || p == BZ_EOS_MAGIC {
                break;
            }
            let b = r.read1();
            w.write(b as u64, 1);
        }
    }
    w.flush()
}

fn compress_std(data: &[u8]) -> Vec<u8> {
    use bzip2::{Compression, write::BzEncoder};
    let mut out = Vec::new();
    let mut enc = BzEncoder::new(&mut out, Compression::new(9));
    enc.write_all(data).unwrap();
    enc.finish().unwrap();
    out
}

fn gen_data(n: usize, seed: u32) -> Vec<u8> {
    let mut d = Vec::with_capacity(n);
    let mut x = seed;
    for i in 0..n {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        // Mix runs and pseudo-random bytes: compressible, multi-block, varied.
        d.push(if i % 64 < 40 {
            (i / 997) as u8
        } else {
            (x >> 24) as u8
        });
    }
    d
}

fn roundtrip(data: &[u8]) -> Vec<u8> {
    let alz = std_to_alz(&compress_std(data));
    let mut out = Vec::new();
    let mut rd = std::io::Cursor::new(&alz);
    extract_bzip2(&mut rd, &mut out, alz.len() as u64, u64::MAX, None).expect("extract_bzip2");
    out
}

#[test]
fn single_block_roundtrips() {
    let data = gen_data(50_000, 1);
    assert_eq!(roundtrip(&data), data);
}

#[test]
fn multi_block_roundtrips() {
    // ~2.4 MB spans multiple ~900 KB blocks. This seed's first block also
    // happens to contain a false "DLZ" marker in its payload, exercising the
    // decode-validated boundary search.
    let data = gen_data(2_400_000, 0x12345678);
    assert_eq!(roundtrip(&data), data);
}

#[test]
fn various_sizes_roundtrip() {
    for (i, &sz) in [900_001usize, 1_000_000, 1_800_050].iter().enumerate() {
        let data = gen_data(sz, 0xABCD00 + i as u32);
        assert_eq!(roundtrip(&data), data, "size {sz} failed to round-trip");
    }
}

#[test]
fn output_cap_is_enforced() {
    // Extraction must stop once more than the declared size is produced.
    let data = gen_data(2_000_000, 7);
    let alz = std_to_alz(&compress_std(&data));
    let mut out = Vec::new();
    let mut rd = std::io::Cursor::new(&alz);
    let err = extract_bzip2(&mut rd, &mut out, alz.len() as u64, 1000, None).is_err();
    assert!(
        err,
        "expected UncompressedSizeExceeded when output exceeds cap"
    );
}
