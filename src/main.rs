//! `unalz`: command-line ALZ archive extractor.

use std::io::Read;
use std::path::Path;
use std::process;

use unalz::archive::{
    ATTR_ARCHIVE, ATTR_DIRECTORY, ATTR_HIDDEN, ATTR_READONLY, ATTR_SYMLINK, AlzArchive,
    archive_totals,
};
use unalz::dostime::dos_datetime_to_string;
use unalz::extract;

const USAGE: &str = "\
usage: unalz [-l] [-p] [-q] [-d DIR] [--pwd PASSWORD] <archive.alz | -> [files...]

  -l, --list      list archive contents
  -p              extract to stdout (pipe)
  -q, --quiet     suppress progress messages
  -d DIR          output directory (default: .)
  --pwd PASSWORD  decryption password
  -h, --help      show this help
  -V, --version   show version";

struct Cli {
    list: bool,
    pipe: bool,
    quiet: bool,
    dest_dir: Option<String>,
    password: Option<String>,
    archive: String,
    files: Vec<String>,
}

fn parse_args() -> Result<Cli, String> {
    let mut list = false;
    let mut pipe = false;
    let mut quiet = false;
    let mut dest_dir = None;
    let mut password = None;
    let mut positional: Vec<String> = Vec::new();
    let mut rest_positional = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if rest_positional {
            positional.push(arg);
            continue;
        }
        match arg.as_str() {
            "-l" | "--list" => list = true,
            "-p" => pipe = true,
            "-q" | "--quiet" => quiet = true,
            "-d" => dest_dir = Some(args.next().ok_or("-d requires a directory")?),
            "--pwd" => password = Some(args.next().ok_or("--pwd requires a password")?),
            "-h" | "--help" => {
                println!("{USAGE}");
                process::exit(0);
            }
            "-V" | "--version" => {
                println!("unalz {}", env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            "--" => rest_positional = true,
            s if s.starts_with("--pwd=") => password = Some(s["--pwd=".len()..].to_string()),
            s if s.starts_with("-d") && s.len() > 2 => dest_dir = Some(s[2..].to_string()),
            s if s != "-" && s.starts_with('-') => return Err(format!("unknown option: {s}")),
            _ => positional.push(arg),
        }
    }

    if positional.is_empty() {
        return Err("no archive specified".into());
    }
    let archive = positional.remove(0);
    Ok(Cli {
        list,
        pipe,
        quiet,
        dest_dir,
        password,
        archive,
        files: positional,
    })
}

fn main() {
    let cli = match parse_args() {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            process::exit(2);
        }
    };

    let quiet = cli.quiet || cli.pipe;

    let mut archive = if cli.archive == "-" {
        let mut data = Vec::new();
        if let Err(e) = std::io::stdin().read_to_end(&mut data) {
            eprintln!("err: {e}");
            process::exit(1);
        }
        match AlzArchive::from_bytes(data) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("file open error : stdin");
                eprintln!("err: {e}");
                process::exit(1);
            }
        }
    } else {
        match AlzArchive::open(&cli.archive) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("file open error : {}", cli.archive);
                eprintln!("err: {e}");
                process::exit(1);
            }
        }
    };

    if cli.list {
        list_archive(&archive, &cli.archive);
        return;
    }

    let password = if archive.is_encrypted {
        if let Some(ref pwd) = cli.password {
            Some(pwd.clone())
        } else if cli.archive == "-" {
            eprintln!("err: encrypted archive from stdin requires --pwd");
            process::exit(1);
        } else {
            match rpassword::prompt_password("Enter Password : ") {
                Ok(pwd) => Some(pwd),
                Err(e) => {
                    eprintln!("err: {e}");
                    process::exit(1);
                }
            }
        }
    } else {
        cli.password.clone()
    };

    let dest_dir = cli.dest_dir.as_deref().unwrap_or(".");
    let dest_path = Path::new(dest_dir);

    if !quiet {
        eprintln!("\nExtract {} to {}", cli.archive, dest_dir);
    }

    let result = if cli.files.is_empty() {
        extract::extract_all(
            &mut archive,
            dest_path,
            password.as_deref(),
            cli.pipe,
            quiet,
        )
    } else {
        extract::extract_files(
            &mut archive,
            dest_path,
            &cli.files,
            password.as_deref(),
            cli.pipe,
            quiet,
        )
    };

    match result {
        Ok(()) => {
            if !quiet {
                eprintln!("\ndone.");
            }
        }
        Err(e) => {
            eprintln!("\nextract failed: {e}");
            process::exit(1);
        }
    }
}

fn list_archive(archive: &AlzArchive, source: &str) {
    println!("\nListing archive: {source}");
    println!();
    println!("Attr   Uncomp Size    Comp Size Method  Date & Time & File Name");
    println!(
        "----- ------------ ------------ ------- ------------------------------------------------"
    );

    for entry in &archive.entries {
        let a = entry.file_attribute;
        let attr = format!(
            "{}{}{}{}{}",
            if a & ATTR_ARCHIVE != 0 { "A" } else { "_" },
            if a & ATTR_DIRECTORY != 0 { "D" } else { "_" },
            if a & ATTR_SYMLINK != 0 { "S" } else { "_" },
            if a & ATTR_READONLY != 0 { "R" } else { "_" },
            if a & ATTR_HIDDEN != 0 { "H" } else { "_" },
        );

        let datetime = dos_datetime_to_string(entry.file_time_date);
        let encrypted = if entry.is_encrypted() { "*" } else { "" };

        println!(
            "{attr} {:>12} {:>12} {:<7} {datetime}  {}{encrypted}",
            entry.uncompressed_size,
            entry.compressed_size,
            entry.compression_method,
            entry.file_name,
        );
    }

    let (total_uncompressed, total_compressed, file_count) = archive_totals(&archive.entries);

    println!(
        "----- ------------ ------------ ------- ------------------------------------------------"
    );
    let plural = if file_count <= 1 { "" } else { "s" };
    println!(
        "      {total_uncompressed:>12} {total_compressed:>12}         Total {file_count} file{plural}"
    );
}
