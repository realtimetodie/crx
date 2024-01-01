#![forbid(unsafe_code)]
use clap::{ArgAction, ArgMatches};
use crx::{error::Error, Crx};
use ecdsa::VerifyingKey as EcdsaVerifyingKey;
use p256::NistP256;
use pkcs8::{
    der::{pem::LineEnding, SecretDocument},
    DecodePublicKey, EncodePublicKey as _, EncryptedPrivateKeyInfo,
};
use rsa::RsaPublicKey;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cmd = clap::Command::new("crx")
        .bin_name("crx")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .subcommand(
            clap::Command::new("sign")
                .about("Sign a web extension archive and create a CRX package")
                .arg(
                    clap::arg!(--"key" <key>)
                        .help("The path to the file that contains the private key. This file must use the PKCS #8 DER format. Multiple private keys can be supplied to sign the CRX package. The first private key will be used to generate the unique ID.")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf))
                        .action(ArgAction::Append)
                        .num_args(1),
                )
                .arg(
                    clap::arg!(--"password" <password>)
                        .help("Optional. The private key password, which is required if the private key is password protected.")
                        .value_parser(clap::value_parser!(String))
                        .requires("key")
                        .action(ArgAction::Append)
                        .num_args(1),
                )
                .arg(
                    clap::arg!(--"out" <output>)
                        .help("Optional. The path to the directory where to save the signed CRX package. If not set, the CRX package is saved in the current working directory.")
                        .value_parser(clap::value_parser!(PathBuf))
                        .action(ArgAction::Set)
                        .num_args(1),
                )
                .arg(
                    clap::arg!(<path>)
                        .help("The path to the web extension archive.")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf))
                        .num_args(1),
                )
        )
        .subcommand(
            clap::Command::new("info")
                .about("Print information of a CRX package")
                .arg(
                    clap::arg!(<path>)
                        .help("The path to the CRX package.")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf))
                        .num_args(1),
                )
        )
        .subcommand(
            clap::Command::new("verify")
                .about("Verify the integrity of a CRX package")
                .arg(
                    clap::arg!(<path>)
                        .help("The path to the CRX package.")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf))
                        .num_args(1),
                )
        )
        .subcommand(
            clap::Command::new("extract")
                .about("Extract the web extension archive from a CRX package")
                .arg(
                    clap::arg!(--"out" <output>)
                        .help("Optional. The path to the directory where to save the web extension archive. If not set, the web extension archive is saved in the current working directory.")
                        .value_parser(clap::value_parser!(PathBuf))
                        .action(ArgAction::Set)
                        .num_args(1),
                )
                .arg(
                    clap::arg!(<path>)
                        .help("The path to the CRX package.")
                        .required(true)
                        .value_parser(clap::value_parser!(PathBuf))
                        .num_args(1),
                )
        );

    match cmd.get_matches().subcommand() {
        Some(("sign", sub_matches)) => handle_sign(sub_matches),
        Some(("info", sub_matches)) => handle_info(sub_matches),
        Some(("verify", sub_matches)) => handle_verify(sub_matches),
        Some(("extract", sub_matches)) => handle_extract(sub_matches),
        _ => unreachable!(),
    }
}

fn handle_sign(sub_matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let path = sub_matches
        .get_one::<std::path::PathBuf>("path")
        .expect("Missing file path");

    let file = File::open(path)?;
    let mut archive_data = Vec::new();
    let mut buf_reader = BufReader::new(file);
    buf_reader.read_to_end(&mut archive_data)?;

    let secret_docs = collect_secret_docs(sub_matches)?;

    let mut rng = rand::thread_rng();

    let crx = Crx::try_sign_with_rng(&mut rng, secret_docs, &archive_data)?;

    let crx_file = {
        let mut out_path = sub_matches
            .get_one::<PathBuf>("out")
            .unwrap_or(path)
            .to_owned();

        // Determine whether the output path is a directory
        if out_path.is_dir() {
            out_path.set_file_name(path.file_name().unwrap());
            out_path.set_extension("crx");
        }

        File::create(out_path)?
    };
    let mut buf_writer = BufWriter::new(crx_file);
    buf_writer.write_all(&crx.to_crx())?;

    Ok(())
}

fn handle_info(sub_matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let path = sub_matches
        .get_one::<std::path::PathBuf>("path")
        .expect("Missing file path");

    let file = File::open(path)?;
    let filesize = file.metadata().unwrap().len();
    let mut crx_data = Vec::new();
    let mut buf_reader = BufReader::new(file);
    buf_reader.read_to_end(&mut crx_data)?;

    let crx = Crx::try_from(crx_data)?;

    let mut rsa_public_keys: Vec<String> = Vec::with_capacity(0);
    for key_proof in crx.file_header.sha256_with_rsa {
        let rsa_public_key = RsaPublicKey::from_public_key_der(key_proof.public_key())?;

        match rsa_public_key.to_public_key_pem(LineEnding::LF) {
            Ok(public_key_pem) => rsa_public_keys.push(public_key_pem),
            Err(err) => return Err(Box::new(Error::Spki(err))),
        }
    }

    let mut ecdsa_public_keys: Vec<String> = Vec::with_capacity(0);
    for key_proof in crx.file_header.sha256_with_ecdsa {
        let ecdsa_verifying_key: EcdsaVerifyingKey<NistP256> =
            EcdsaVerifyingKey::from_public_key_der(key_proof.public_key())?;

        match ecdsa_verifying_key.to_public_key_pem(LineEnding::LF) {
            Ok(public_key_pem) => ecdsa_public_keys.push(public_key_pem),
            Err(err) => return Err(Box::new(Error::Spki(err))),
        }
    }

    println!("ID {}", crx.id);
    println!("Size: {:?} bytes", filesize);

    if !rsa_public_keys.is_empty() {
        println!("Found RSA key proofs: {} total", rsa_public_keys.len());

        for rsa_public_key in rsa_public_keys.iter() {
            print!("{}", rsa_public_key);
        }
    }

    if !ecdsa_public_keys.is_empty() {
        println!("Found EC key proofs: {} total", ecdsa_public_keys.len());

        for public_key in ecdsa_public_keys.iter() {
            print!("{}", public_key);
        }
    }

    Ok(())
}

fn handle_verify(sub_matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let path = sub_matches
        .get_one::<std::path::PathBuf>("path")
        .expect("Missing file path");

    let file = File::open(path)?;
    let mut crx_data = Vec::new();
    let mut buf_reader = BufReader::new(file);
    buf_reader.read_to_end(&mut crx_data)?;

    let crx = Crx::try_from(crx_data)?;
    crx.verify()?;

    Ok(())
}

fn handle_extract(sub_matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let path = sub_matches
        .get_one::<std::path::PathBuf>("path")
        .expect("Missing file path");

    let file = File::open(path)?;
    let _filesize = file.metadata().unwrap().len();
    let mut crx_data = Vec::new();
    let mut buf_reader = BufReader::new(file);
    buf_reader.read_to_end(&mut crx_data)?;

    let crx = Crx::try_from(crx_data)?;

    let archive_file = {
        let mut out_path = sub_matches
            .get_one::<PathBuf>("out")
            .unwrap_or(path)
            .to_owned();

        // Determine whether the output path is a directory
        if out_path.is_dir() {
            out_path.set_file_name(path.file_name().unwrap());
            out_path.set_extension("zip");
        }

        File::create(out_path)?
    };
    let mut buf_writer = BufWriter::new(archive_file);
    buf_writer.write_all(crx.as_bytes())?;

    Ok(())
}

// Collect the private keys.
fn collect_secret_docs(
    sub_matches: &ArgMatches,
) -> Result<Vec<SecretDocument>, Box<dyn std::error::Error>> {
    sub_matches
        .get_many::<std::path::PathBuf>("key")
        .expect("No private key")
        .map(|path| {
            // TODO
            let password = String::new();

            if sub_matches.contains_id("password") {
                let mut file = File::open(path)?;

                let metadata = std::fs::metadata(path)?;
                let mut pem_data = vec![0; metadata.len() as usize];
                file.read_exact(&mut pem_data).expect("Buffer overflow");

                let encrypted_private_key = EncryptedPrivateKeyInfo::try_from(pem_data.as_slice())?;
                let secret_doc = encrypted_private_key.decrypt(password)?;

                Ok(secret_doc)
            } else {
                let (_, secret_doc) = SecretDocument::read_pem_file(path)?;

                Ok(secret_doc)
            }
        })
        .collect()
}
