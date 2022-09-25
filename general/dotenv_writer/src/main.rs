use clap::{Parser, ValueHint};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone)]
struct KeyValue {
    key: String,
    value: String,
}

impl FromStr for KeyValue {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.split_once('=')
            .ok_or("could not parse string..is there a '=' in the input string?")
            .map(|v| Self {
                key: v.0.to_string(),
                value: v.1.to_string(),
            })
    }
}

impl fmt::Display for KeyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.key, self.value)
    }
}

fn write_to_file(kv_pairs: &[KeyValue], out_dir: &Path) {
    let mut out_file = out_dir.to_path_buf();
    if !out_file.is_dir() {
        panic!("path given is not a directory!");
    }

    out_file.push(".env");

    let mut contents = kv_pairs
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>()
        .join("\n");
    contents.push('\n');

    std::fs::write(out_file, contents).unwrap();
}

/// Simple utility to create a .env file
#[derive(Parser, Debug)]
#[clap(author, version)]
struct Args {
    /// A list of key-value pairs to write to the .env file
    #[clap(short = 'D', long = "define", number_of_values = 1)]
    keyvalues: Vec<KeyValue>,

    /// Output directory where a .env file will be created
    #[clap(short, long, parse(from_os_str), value_hint = ValueHint::DirPath)]
    output: PathBuf,
}

fn main() {
    let args = Args::parse();
    write_to_file(&args.keyvalues, &args.output);
}
