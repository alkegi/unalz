# unalz

[![crates.io](https://img.shields.io/crates/v/unalz.svg)](https://crates.io/crates/unalz)
[![docs.rs](https://img.shields.io/docsrs/unalz)](https://docs.rs/unalz)
[![CI](https://github.com/alkegi/unalz/actions/workflows/ci.yml/badge.svg)](https://github.com/alkegi/unalz/actions/workflows/ci.yml)

ALZ archive extractor written in Rust.

## Usage

```
unalz archive.alz                 # extract all files
unalz archive.alz file.txt        # extract a specific file
unalz -d output/ archive.alz      # extract to a directory
unalz --pwd SECRET archive.alz    # extract an encrypted archive
unalz -l archive.alz              # list contents
unalz -p archive.alz file.txt     # extract to stdout
cat archive.alz | unalz -l -      # read from stdin
```

## Supported Features

### Compression
- Store (no compression)
- Deflate
- Bzip2 (ALZ-modified)

### Encryption
- ZipCrypto (traditional PKWARE)

### Archive types
- Split (multi-volume) archives (`.alz`, `.a00`, `.a01`, ...)

### Other
- CP949/EUC-KR filename decoding to UTF-8
- CRC32 verification
- DOS timestamp preservation

## Docs

[https://github.com/alkegi/docs](https://github.com/alkegi/docs)

## Reference

- [`unalz`](https://github.com/kippler/unalz) - original C/C++ implementation by kippler
