# crx

A library to read and write CRX packages.

## About

Chrome web extensions and themes are packaged as CRX packages using asymmetric keys.

The CRX package format prepends a Protocol Buffer to a message that can contain an unlimited number of public key and signature proofs.

Supported key sizes and EC curves

- RSA `1.2.840.113549.1.1.1`: 1024, 2048, 4096
- EC `1.2.840.10045.2.1`: NIST P-256

## Example

Signing, verifying and writing a Chrome web extension as a CRX package

```rust
use crx::Crx;
use pkcs8::der::SecretDocument;
use rand::thread_rng;
use std::fs;

let zip = fs::read("test/extension.zip")?;

let (_, secret_doc) = SecretDocument::read_pem_file("test/rsa2048-key.pem")?;
let secret_docs = vec![secret_doc];

let mut rng = thread_rng();

let crx = Crx::try_sign_with_rng(&mut rng, secret_docs, &zip)?;
assert!(crx.verify().is_ok());

println!("Chrome web extension ID: {}", crx.id);

fs::write("test/extension.crx", crx.to_crx())?;
```

Reading and extracting a Chrome web extension archive from a CRX package

```rust
use crx::Crx;
use std::fs;

let crx = Crx::read_crx_file("extension.crx")?;
assert!(crx.verify().is_ok());

println!("Chrome web extension ID: {}", crx.id);

fs::write("extension.zip", crx.as_bytes())?;
```

## Command line tool

```txt
Usage: crx <COMMAND>

Commands:
  sign      Sign a web extension archive and create a CRX package
  info      Print information of a CRX package
  verify    Verify the integrity of a CRX package
  extract   Extract the web extension archive from a CRX package
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Signing a web extension archive and creating a CRX package

```
$ crx sign --key rsa.pem extension.zip
```

This will output a new CRX package `extension.crx` in the current working directory.

When you sign a CRX package using the crx command line tool, you must provide the signer's private key using the `--key` option.

Usually, you sign a CRX package using only one signer. If you need to sign a CRX package using multiple signatures, use the `--key` option multiple times.

You can specify the output directory using the `--out` option.

```
$ crx sign --key rsa.pem --out=example.crx extension.zip
```

### Verifying the integrity of a CRX package

```
$ crx verify --key rsa.pem extension.crx
```

This will validate the signatures of the CRX package. If you need to verify a CRX package using multiple signatures, use the `--key` option multiple times.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/crx
[crate-link]: https://crates.io/crates/crx
[doc-image]: https://docs.rs/crx/badge.svg
[doc-link]: https://docs.rs/crx
[build-image]: https://github.com/browserbuild/crx/workflows/CI/badge.svg
[build-link]: https://github.com/browserbuild/crx/actions?query=workflow%3ACI+branch%3Amain
[deps-image]: https://deps.rs/repo/github/browserbuild/crx/status.svg
[deps-link]: https://deps.rs/repo/github/browserbuild/crx
[msrv-image]: https://img.shields.io/badge/rustc-1.65+-blue.svg
