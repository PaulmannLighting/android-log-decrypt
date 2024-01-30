use android_log_decrypt::decrypt;
use clap::Parser;
use clap_stdin::FileOrStdin;
use log::error;
use rpassword::prompt_password;
use std::io::{stdout, BufWriter, Write};
use std::process::exit;

#[derive(Debug, Parser)]
struct Args {
    #[arg(index = 1, help = "path to the encrypted log file")]
    logfile: FileOrStdin<String>,
    #[arg(long, short, help = "hexadecimal decryption key")]
    key: Option<String>,
}

impl Args {
    #[must_use]
    pub fn hex_key(&self) -> String {
        self.key.clone().unwrap_or_else(|| {
            prompt_password("Decryption key: ").unwrap_or_else(|error| {
                error!("{error}");
                exit(1)
            })
        })
    }

    pub fn key(&self) -> Vec<u8> {
        hex::decode(self.hex_key()).unwrap_or_else(|error| {
            error!("{error}");
            exit(2);
        })
    }
}

fn main() {
    env_logger::init();

    let args = Args::parse();
    let ciphertext = args.logfile.clone().contents().unwrap_or_else(|error| {
        error!("{error}");
        exit(3)
    });
    let plain_text = decrypt(&ciphertext, &args.key()).unwrap_or_else(|error| {
        error!("{error}");
        exit(4);
    });
    BufWriter::new(stdout().lock())
        .write_all(&plain_text)
        .unwrap_or_else(|error| {
            error!("{error}");
            exit(5);
        });
}
