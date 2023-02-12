#![forbid(unsafe_code)]
use crx::{Id, Keyset};
use pkcs8::der::SecretDocument;
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    str::FromStr,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cmd = clap::Command::new("crx")
        .bin_name("crx")
        .subcommand_required(true)
        .subcommand(
            clap::Command::new("sign")
                .about("Sign a Chrome Web Extension")
                .arg(
                    clap::arg!(--"key" <filename>)
                        .help("The name of the file that contains the signer's private key. This file must use the PKCS #8 DER format.")
                        .required(true)
                        .value_parser(clap::value_parser!(std::path::PathBuf)),
                )
                .arg(
                    clap::arg!(--"key-pass" <format>)
                        .help("The password for the signer's private key, which is needed if the private key is password protected.")
                        .value_parser(clap::value_parser!(std::path::PathBuf)),
                )
                .arg(
                    clap::arg!(--"out" <filename>)
                        .help("The location where you'd like to save the signed CRX. If this option isn't provided explicitly, the CRX package is saved next to the input Chrome Web Extension archive.")
                        .value_parser(clap::value_parser!(std::path::PathBuf)),
                )
                .arg(
                    clap::arg!(<archive>)
                        .help("The name of the archive.")
                        .required(true)
                        .value_parser(clap::value_parser!(std::path::PathBuf)),
                )
        );

    match cmd.get_matches().subcommand() {
        Some(("sign", sub_matches)) => {
            let path = sub_matches
                .get_one::<std::path::PathBuf>("archive")
                .expect("No archive");

            let file = File::open(path)?;
            let mut archive_data = Vec::new();
            let mut buf_reader = BufReader::new(file);
            buf_reader.read_to_end(&mut archive_data)?;

            let secret_docs = sub_matches
                .get_many::<std::path::PathBuf>("key")
                .expect("No private key")
                .into_iter()
                .map(|path| {
                    let file = File::open(path)?;

                    let mut buf_reader = BufReader::new(file);
                    let mut pem_data = String::new();
                    buf_reader
                        .read_to_string(&mut pem_data)?;

                    // EncryptedPrivateKeyInfo decrypt

                    let (_, secret_doc) =
                        SecretDocument::from_pem(&pem_data)?;

                    Ok(secret_doc)
                })
                .collect::<Result<Vec<SecretDocument>, Box<dyn std::error::Error>>>()?;

            let digest = "edf2454ebdddf3ef647bfa8676c56c41".to_string();
            let id = Id::from_str(&digest).unwrap();

            let crx_keyset = Keyset::new(id, secret_docs);

            let mut rng = rand::thread_rng();

            let crx = crx_keyset.try_sign_with_rng(&mut rng, &archive_data)?;

            let mut path = path.to_owned();
            let x = path.set_extension("crx");

            let file = File::create(path)?;
            let mut buf_writer = BufWriter::new(file);
            buf_writer.write_all(&crx)?;

            Ok(())
        }
        _ => unreachable!(),
    }
}
