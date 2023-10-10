use android_log_decrypt::decrypt;
use clap::Parser;
use std::fs::read_to_string;
use std::io::{stdout, Write};
use std::path::PathBuf;
use std::process::exit;

#[derive(Debug, Parser)]
struct Args {
    #[arg(index = 1, help = "path to the log file")]
    filename: PathBuf,
    #[arg(long, short, help = "decryption ")]
    key: String,
}

fn main() {
    let args = Args::parse();
    let ciphertext = read_to_string(&args.filename).unwrap_or_else(|_| {
        eprintln!("Could not read file: {:?}", args.filename);
        exit(1);
    });
    let password = hex::decode(&args.key).unwrap_or_else(|_| {
        eprintln!("Invalid hex key: {}", args.key);
        exit(2);
    });
    let plain_text = decrypt(&ciphertext, &password).unwrap_or_else(|error| {
        eprintln!("{error}");
        exit(3);
    });
    stdout().write_all(&plain_text).unwrap_or_else(|error| {
        eprintln!("{error}");
        exit(4);
    });
}
