//! Sample-archive test: extract every archive under tests/data/ and verify each
//! internal file against its recorded (path, length, CRC-32). The archives come
//! from real archiver builds across versions and options; many hold identical
//! content compressed differently, so agreement across them independently
//! confirms each codec and option path. Extraction already checks per-entry CRC,
//! so a passing run is byte-exact, not merely error-free.

use std::path::Path;

use unalz::archive::AlzArchive;

// (archive, password, &[(path, len, crc)])
#[allow(clippy::type_complexity)] // a test-data table, not a public API type
const SAMPLES: &[(&str, Option<&str>, &[(&str, u64, u32)])] = &[
    ("bzip2_dlz.alz", None, &[("text.txt", 3600, 0x2c19aec0)]),
    (
        "deflate_empty.alz",
        None,
        &[
            ("empty.txt", 0, 0x00000000),
            ("precompressed.gz", 95, 0x6a94d1bc),
            ("prog.sys", 2060, 0xb54ccab2),
            ("random.bin", 4096, 0x1bb92dfc),
            ("text.txt", 3150, 0x7a553a9d),
        ],
    ),
    ("deflate_pure.alz", None, &[("text.txt", 9000, 0x1859c604)]),
    (
        "enc_deflate.alz",
        Some("test1234"),
        &[("a.txt", 3150, 0x7a553a9d), ("b.bin", 512, 0x7735137b)],
    ),
    (
        "enc_store.alz",
        Some("test1234"),
        &[("text.txt", 3600, 0x2c19aec0)],
    ),
    (
        "split_store.alz",
        None,
        &[
            ("part0.bin", 40000, 0xcee0afee),
            ("part1.bin", 40000, 0x00bd73ad),
            ("part2.bin", 40000, 0x18b848e0),
            ("part3.bin", 40000, 0xd0333732),
        ],
    ),
    (
        "store_empty.alz",
        None,
        &[
            ("empty.txt", 0, 0x00000000),
            ("precompressed.gz", 95, 0x6a94d1bc),
            ("prog.sys", 2060, 0xb54ccab2),
            ("random.bin", 4096, 0x1bb92dfc),
            ("text.txt", 3150, 0x7a553a9d),
        ],
    ),
    ("store_old.alz", None, &[("text.txt", 3600, 0x2c19aec0)]),
];

fn data(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
        .to_str()
        .unwrap()
        .to_string()
}

#[test]
fn samples_extract_and_verify() {
    for (arc, pwd, expected) in SAMPLES {
        let path = data(arc);
        assert!(Path::new(&path).is_file(), "missing sample archive: {path}");

        let mut archive = AlzArchive::open(&path).unwrap();
        let tmp = std::env::temp_dir().join(format!(
            "unalz_sample_{}",
            Path::new(arc).file_stem().unwrap().to_str().unwrap()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        unalz::extract::extract_all(&mut archive, &tmp, *pwd, false, true)
            .unwrap_or_else(|e| panic!("{arc}: extract failed: {e}"));

        for (name, len, crc) in *expected {
            let got =
                std::fs::read(tmp.join(name)).unwrap_or_else(|_| panic!("{arc}: missing {name}"));
            assert_eq!(got.len() as u64, *len, "{arc}: {name} wrong length");
            assert_eq!(crc32fast::hash(&got), *crc, "{arc}: {name} wrong CRC");
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
