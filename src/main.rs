use android_log_decrypt::decrypt;
use clap::Parser;
use log::error;
use std::fs::read_to_string;
use std::io::{stdout, Write};
use std::path::PathBuf;
use std::process::exit;

#[derive(Debug, Parser)]
struct Args {
    #[arg(index = 1, help = "path to the encrypted log file")]
    filename: PathBuf,
    #[arg(long, short, help = "hexadecimal decryption key")]
    key: String,
}

fn main() {
    env_logger::init();

    let args = Args::parse();
    let ciphertext = read_to_string(&args.filename).unwrap_or_else(|error| {
        error!("{error}");
        exit(1);
    });
    let key = hex::decode(&args.key).unwrap_or_else(|error| {
        error!("{error}");
        exit(2);
    });
    let plain_text = decrypt(&ciphertext, &key).unwrap_or_else(|error| {
        error!("{error}");
        exit(3);
    });
    stdout().write_all(&plain_text).unwrap_or_else(|error| {
        error!("{error}");
        exit(4);
    });
}
