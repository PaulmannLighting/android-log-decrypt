use android_log_decrypt::decrypt;
use clap::Parser;
use clap_stdin::FileOrStdin;
use log::error;
use rpassword::prompt_password;
use std::io::{stdout, Write};
use std::process::exit;

#[derive(Debug, Parser)]
struct Args {
    #[arg(index = 1, help = "path to the encrypted log file")]
    logfile: FileOrStdin,
    #[arg(long, short, help = "hexadecimal decryption key")]
    key: Option<String>,
}

fn main() {
    env_logger::init();

    let args = Args::parse();
    let ciphertext = args.logfile.to_string();
    let key = hex::decode(args.key.unwrap_or_else(|| {
        prompt_password("Decryption key: ").unwrap_or_else(|error| {
            error!("{error}");
            exit(1)
        })
    }))
    .unwrap_or_else(|error| {
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
