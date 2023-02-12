# crx

A CRX library to sign and verify Chrome Web Extensions using asymmetric keys

## About

The CRX3 package format prepends a Protocol Buffer to a ZIP archive that can contain an unlimited number of public key and signature proofs.

### Supported keys sizes and EC curves

- RSA `1.2.840.113549.1.1.1`: 1024, 2048, 4096
- EC `1.2.840.10045.2.1`: NIST P-256

## Sign a Chrome Web Extension

The command line tool lets you sign Chrome Web Extensions and confirm that a CRX's signature will be verified successfully.

The syntax for signing a Chrome Web Extension using the crx command line tool

```
$ crx sign --key key.pem extension.zip
```

This will output a new CRX package next to the input.

When you sign a Chrome Web Extension using the crx command line tool, you must provide the signer's private key using the `--key` option.

Usually, you sign a Chrome Web Extension using only one signer. If you need to sign a Chrome Web Extension using multiple signers, use the `--key` option multiple times.

## Verify the signature of a CRX

Check whether the CRX's signatures are expected to be confirmed as valid

```
$ crx verify [options] extension.zip
```
