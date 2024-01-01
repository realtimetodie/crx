#![warn(
    clippy::all,
    clippy::dbg_macro,
    clippy::todo,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::mem_forget,
    clippy::unused_self,
    clippy::filter_map_next,
    clippy::needless_continue,
    clippy::needless_borrow,
    clippy::match_wildcard_for_single_variants,
    clippy::if_let_mutex,
    clippy::mismatched_target_os,
    clippy::await_holding_lock,
    clippy::match_on_vec_items,
    clippy::imprecise_flops,
    clippy::suboptimal_flops,
    clippy::lossy_float_literal,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::fn_params_excessive_bools,
    clippy::exit,
    clippy::inefficient_to_string,
    clippy::linkedlist,
    clippy::macro_use_imports,
    clippy::option_option,
    clippy::verbose_file_reads,
    clippy::unnested_or_patterns,
    clippy::str_to_string,
    rust_2018_idioms,
    future_incompatible,
    nonstandard_style,
    missing_debug_implementations,
    missing_docs
)]
#![deny(unreachable_pub)]
#![allow(elided_lifetimes_in_paths, clippy::type_complexity)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]
//! A library to read and write CRX packages.
//!
//! ## About
//!
//! Chrome web extensions and themes are packaged as CRX packages.
//!
//! The CRX package format prepends a Protocol Buffer to a message that can contain an unlimited number of public key and signature proofs.
//!
//! Supported key sizes and EC curves
//!
//! - RSA `1.2.840.113549.1.1.1`: 1024, 2048, 4096
//! - EC `1.2.840.10045.2.1`: NIST P-256
//!
//! ## Example
//!
//! Signing, verifying and writing a Chrome web extension as a CRX package
//!
//! ```
//! use crx::Crx;
//! use pkcs8::der::SecretDocument;
//! use rand::thread_rng;
//! use std::fs;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let zip = fs::read("test/extension.zip")?;
//!
//! let (_, secret_doc) = SecretDocument::read_pem_file("test/rsa2048-key.pem")?;
//! let secret_docs = vec![secret_doc];
//!
//! let mut rng = thread_rng();
//!
//! let crx = Crx::try_sign_with_rng(&mut rng, secret_docs, &zip)?;
//! assert!(crx.verify().is_ok());
//!
//! println!("Chrome web extension ID: {}", crx.id);
//!
//! fs::write("test/extension.crx", crx.to_crx())?;
//! #
//! # Ok(())
//! # }
//! ```
//!
//! Reading and extracting a Chrome web extension from a CRX package
//!
//! ```
//! use crx::Crx;
//! use std::fs;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let crx = Crx::read_crx_file("test/extension.crx")?;
//! assert!(crx.verify().is_ok());
//!
//! println!("Chrome web extension ID: {}", crx.id);
//!
//! fs::write("test/extension.zip", crx.as_bytes())?;
//! #
//! # Ok(())
//! # }
//! ```
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY as EC, RSA_ENCRYPTION as RSA};
use core::fmt::{self, Debug};
use ecdsa::{
    Signature as EcdsaSignature, SignatureEncoding as _, SigningKey as EcdsaSigningKey,
    VerifyingKey,
};
use p256::NistP256;
use pkcs8::{der::Document, DecodePublicKey, EncodePublicKey as _, PrivateKeyInfo, SecretDocument};
use prost::Message as _;
use rsa::{
    pkcs1v15::{Pkcs1v15Sign, SigningKey as Pkcs1v15SigningKey},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};
use signature::{rand_core::CryptoRngCore, RandomizedSigner, Verifier};

#[cfg(feature = "std")]
use std::{fs, num::ParseIntError, path::Path, str::FromStr};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

/// CRX protocol buffer.
#[allow(missing_docs)]
pub mod crx3 {
    include!(concat!(env!("OUT_DIR"), "/crx_file.rs"));
}
pub mod error;

pub use crate::error::{Error, Result};

/// The CRX id size.
pub const CRX_ID_SIZE: usize = 16;

/// The CRX magic number (Cr24).
pub const CRX_MAGIC: &[u8; 4] = b"Cr24";

/// The length of the CRX header section.
pub const CRX_SIZE_HINT: usize = 4;

/// The CRX header.
pub const CRX_HEADER: &[u8; 16] = b"CRX3 SignedData\x00";

/// The CRX version identifier (v3).
pub const CRX_VERSION: [u8; 4] = [3_u8, 0, 0, 0];

#[cfg(target_family = "wasm")]
use rand::thread_rng;

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
pub fn sign(pem: String, data: Vec<u8>) -> Vec<u8> {
    let (_, secret_doc) = SecretDocument::from_pem(&pem).unwrap();
    let secret_docs = vec![secret_doc];

    let mut rng = thread_rng();

    let crx = Crx::try_sign_with_rng(&mut rng, secret_docs, &data).unwrap();
    crx.to_crx()
}

/// CRX proof.
#[derive(Debug)]
pub struct Proof {
    inner: Vec<u8>,
}

impl Proof {
    /// Creates a new instance of an `Proof`.
    pub fn new(crx_signed_data: &[u8], data: Vec<u8>) -> Self {
        let mut proof = Vec::with_capacity(
            CRX_HEADER.len() + CRX_SIZE_HINT + crx_signed_data.len() + data.len(),
        );
        proof.extend(CRX_HEADER);

        let crx_signed_data_size_hint: [u8; CRX_SIZE_HINT] =
            u32::to_le_bytes(crx_signed_data.len() as u32);
        proof.extend(crx_signed_data_size_hint);

        proof.extend(crx_signed_data);
        proof.extend(data);

        Self { inner: proof }
    }
}

impl AsRef<[u8]> for Proof {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

/// CRX.
///
/// This type wraps an encoded CRX package.
#[derive(Clone, Debug)]
pub struct Crx {
    /// CRX ID.
    pub id: Id,

    /// CRX header containing the asymmetric key proof.
    pub file_header: crx3::CrxFileHeader,

    /// CRX data.
    data: Vec<u8>,
}

impl Crx {
    /// Sign a CRX package using a cryptographically secure generator and
    /// create a new instance of an `Crx`.
    pub fn try_sign_with_rng(
        rng: &mut impl CryptoRngCore,
        secret_docs: Vec<SecretDocument>,
        data: &[u8],
    ) -> Result<Self> {
        let secret_doc = secret_docs.first().ok_or(Error::EmptyAsymmetricKeys)?;
        let pkcs8_pki = PrivateKeyInfo::try_from(secret_doc.as_bytes())?;
        let der_public_key = match pkcs8_pki.algorithm.oid {
            #[cfg(feature = "rsa")]
            RSA => {
                let rsa_private_key = RsaPrivateKey::try_from(pkcs8_pki.clone())?;

                rsa_private_key
                    .to_public_key()
                    .to_public_key_der()
                    .map_err(|e| e.into())
            }
            #[cfg(feature = "ecdsa")]
            EC => {
                let ecdsa_signing_key: EcdsaSigningKey<NistP256> =
                    EcdsaSigningKey::try_from(pkcs8_pki.clone())?;

                ecdsa_signing_key
                    .verifying_key()
                    .to_public_key_der()
                    .map_err(|e| e.into())
            }
            _ => Err(Error::OidUnknown {
                oid: pkcs8_pki.algorithm.oid,
            }),
        }?;

        let crx_id = Id::try_from(&der_public_key)?;

        let crx_signed_data = crx3::SignedData {
            crx_id: Some(crx_id.to_vec()),
        }
        .encode_to_vec();

        let crx_proof = Proof::new(&crx_signed_data, data.to_vec());

        #[cfg(feature = "rsa")]
        let mut rsa_key_proofs = Vec::with_capacity(0);

        #[cfg(feature = "ecdsa")]
        let mut ecdsa_key_proofs = Vec::with_capacity(0);

        secret_docs.iter().try_for_each(|secret_doc| {
            let pkcs8_pki = PrivateKeyInfo::try_from(secret_doc.as_bytes())?;

            match pkcs8_pki.algorithm.oid {
                #[cfg(feature = "rsa")]
                RSA => {
                    let rsa_private_key = RsaPrivateKey::try_from(pkcs8_pki.clone())?;

                    let der_public_key = rsa_private_key.to_public_key().to_public_key_der()?;

                    let rsa_signing_key = Pkcs1v15SigningKey::<Sha256>::new(rsa_private_key);
                    let pkcs1v15_signature = rsa_signing_key.sign_with_rng(rng, crx_proof.as_ref());

                    rsa_key_proofs.push((der_public_key, pkcs1v15_signature.to_vec()));

                    Ok(())
                }
                #[cfg(feature = "ecdsa")]
                EC => {
                    let ecdsa_signing_key: EcdsaSigningKey<NistP256> =
                        EcdsaSigningKey::try_from(pkcs8_pki.clone())?;

                    let der_public_key = ecdsa_signing_key.verifying_key().to_public_key_der()?;

                    let ecdsa_signature: EcdsaSignature<NistP256> =
                        ecdsa_signing_key.try_sign_with_rng(rng, crx_proof.as_ref())?;

                    ecdsa_key_proofs
                        .push((der_public_key, ecdsa_signature.to_der().as_bytes().to_vec()));

                    Ok(())
                }
                _ => Err(Error::OidUnknown {
                    oid: pkcs8_pki.algorithm.oid,
                }),
            }
        })?;

        let crx_file_header = crx3::CrxFileHeader {
            #[cfg(feature = "rsa")]
            sha256_with_rsa: rsa_key_proofs
                .iter()
                .map(|(public_key, signature)| crx3::AsymmetricKeyProof {
                    public_key: Some(public_key.to_owned().into_vec()),
                    signature: Some(signature.to_owned()),
                })
                .collect(),
            #[cfg(feature = "ecdsa")]
            sha256_with_ecdsa: ecdsa_key_proofs
                .iter()
                .map(|(public_key, signature)| crx3::AsymmetricKeyProof {
                    public_key: Some(public_key.to_owned().into_vec()),
                    signature: Some(signature.to_owned()),
                })
                .collect(),
            signed_header_data: Some(crx_signed_data),
        };

        Ok(Self {
            id: crx_id,
            file_header: crx_file_header,
            data: data.to_vec(),
        })
    }

    /// Verify the integrity of a CRX package.
    pub fn verify(&self) -> Result<()> {
        if self.file_header.sha256_with_rsa.is_empty()
            && self.file_header.sha256_with_ecdsa.is_empty()
        {
            return Err(Error::MissingAsymmetricProofs);
        }

        let signed_header_data = self.file_header.signed_header_data();

        let crx_proof = Proof::new(signed_header_data, self.data.to_owned());

        #[cfg(feature = "rsa")]
        if !self.file_header.sha256_with_rsa.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(crx_proof.as_ref());
            let digest = hasher.finalize();

            for key_proof in self.file_header.sha256_with_rsa.iter() {
                let public_key = key_proof.public_key();
                let rsa_public_key = RsaPublicKey::from_public_key_der(public_key)?;

                let signature = key_proof.signature();
                rsa_public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, signature)?;
            }
        }

        #[cfg(feature = "ecdsa")]
        if !self.file_header.sha256_with_ecdsa.is_empty() {
            for key_proof in self.file_header.sha256_with_ecdsa.iter() {
                let signature = key_proof.signature();
                let ecdsa_signature = EcdsaSignature::<NistP256>::from_der(signature)?;

                let public_key = key_proof.public_key();
                let ecdsa_verifying_key =
                    VerifyingKey::<NistP256>::from_public_key_der(public_key)?;

                ecdsa_verifying_key.verify(crx_proof.as_ref(), &ecdsa_signature)?;
            }
        }

        Ok(())
    }

    /// Read a CRX package from a file.
    #[cfg(feature = "std")]
    pub fn read_crx_file(path: impl AsRef<Path>) -> Result<Self> {
        fs::read(path)?.try_into()
    }

    /// Write CRX package to a file.
    #[cfg(feature = "std")]
    pub fn write_crx_file(&self, path: impl AsRef<Path>) -> Result<()> {
        Ok(fs::write(path, self.to_crx())?)
    }

    /// Return a CRX package.
    pub fn to_crx(&self) -> Vec<u8> {
        let crx_file_header = self.file_header.encode_to_vec();

        let mut crx_data = Vec::with_capacity(
            CRX_MAGIC.len()
                + CRX_VERSION.len()
                + CRX_SIZE_HINT
                + crx_file_header.len()
                + self.data.len(),
        );

        crx_data.extend(CRX_MAGIC);
        crx_data.extend(CRX_VERSION);

        let crx_file_header_size_hint: [u8; CRX_SIZE_HINT] =
            u32::to_le_bytes(crx_file_header.len() as u32);
        crx_data.extend(crx_file_header_size_hint);

        crx_data.extend(crx_file_header);
        crx_data.extend(&self.data);

        crx_data
    }

    /// Get the data of this CRX package.
    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl TryFrom<Vec<u8>> for Crx {
    type Error = Error;

    fn try_from(crx_data: Vec<u8>) -> Result<Self> {
        if crx_data.len() < CRX_MAGIC.len() + CRX_VERSION.len() + CRX_SIZE_HINT {
            return Err(Error::InvalidSize);
        }

        // Try to parse the CRX signature
        let crx_magic = &crx_data[0..CRX_MAGIC.len()];
        if crx_magic != CRX_MAGIC {
            return Err(Error::InvalidMagicNumber);
        }

        let offset = CRX_MAGIC.len();
        let crx_version = &crx_data[offset..offset + CRX_VERSION.len()];
        if crx_version != CRX_VERSION {
            return Err(Error::UnsupportedVersion);
        }

        let offset = offset + CRX_VERSION.len();

        let crx_header_length = u32::from_le_bytes(
            crx_data[offset..offset + CRX_SIZE_HINT]
                .try_into()
                .expect("Failed to get CRX header length"),
        );
        if crx_header_length == 0 {
            return Err(Error::InvalidFileHeaderSize);
        }

        let offset = offset + CRX_SIZE_HINT;
        let crx_file_header =
            crx3::CrxFileHeader::decode(&crx_data[offset..offset + crx_header_length as usize])?;

        let signed_header_data = crx_file_header.signed_header_data();

        let crx_signed_data = crx3::SignedData::decode(signed_header_data)?;

        let crx_id_data = crx_signed_data.crx_id();
        if crx_id_data.len() != CRX_ID_SIZE {
            return Err(Error::InvalidIdSize);
        }

        let crx_id = Id::try_from(crx_id_data)?;

        let offset = offset + crx_header_length as usize;

        Ok(Self {
            id: crx_id,
            file_header: crx_file_header,
            data: crx_data[offset..crx_data.len()].to_vec(),
        })
    }
}

impl AsRef<[u8]> for Crx {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// CRX ID.
///
/// ```
/// use crx::Id;
/// use std::num::ParseIntError;
/// use std::str::FromStr;
///
/// # fn main() -> Result<(), ParseIntError> {
/// // The sha256 digest of an ASN.1 DER-encoded public key
/// let digest = "e3b0c44298fc1c149afbf4c8996fb924".to_string();
/// let id = Id::from_str(&digest)?;
///
/// // Chrome web extension ID
/// assert_eq!(format!("{}", id), "odlameecjipmbmbejkplpemijjgpljce");
/// #
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct Id {
    bytes: [u8; CRX_ID_SIZE],
}

impl Id {
    /// Create a new [`Id`] from a 32 character hexadecimal byte slice.
    pub fn new(bytes: [u8; CRX_ID_SIZE]) -> Self {
        Self { bytes }
    }

    /// Convert this [`Id`] into a new `Vec`.
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

#[cfg(feature = "std")]
impl FromStr for Id {
    type Err = ParseIntError;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Ok(Self {
            bytes: (0..s.len())
                .take(CRX_ID_SIZE * 2)
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
                .collect::<core::result::Result<Vec<u8>, ParseIntError>>()?
                .as_slice()
                .try_into()
                .expect("Failed to create sized slice"),
        })
    }
}

impl TryFrom<&Document> for Id {
    type Error = Error;

    fn try_from(der: &Document) -> Result<Self> {
        let mut hasher = Sha256::new();
        hasher.update(der.clone());

        Ok(Self {
            bytes: hasher.finalize()[0..CRX_ID_SIZE]
                .try_into()
                .map_err(|_| Error::InvalidIdSize)?,
        })
    }
}

impl TryFrom<&[u8]> for Id {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            bytes: bytes.try_into().map_err(|_| Error::InvalidIdSize)?,
        })
    }
}

impl TryFrom<Vec<u8>> for Id {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self {
            bytes: bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidIdSize)?,
        })
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

/// Formats the [`Id`] as a Chrome compatible web extension ID (UTF-8 encoded mpdecimal).
impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            f.write_str(
                &char::from_u32(97 + ((byte >> 4) & 0xf) as u32)
                    .expect("Failed to convert char")
                    .to_string(),
            )?;
            f.write_str(
                &char::from_u32((97 + (byte & 0xf)) as u32)
                    .expect("Failed to convert char")
                    .to_string(),
            )?;
        }

        Ok(())
    }
}

/// Formats the [`Id`] using hexadecimal encoding.
impl Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Id(")?;

        for byte in self.bytes {
            write!(f, "{:02x}", byte)?;
        }

        f.write_str(")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARCHIVE: &[u8] = include_bytes!("../test/extension.zip");

    const RSA_PEM: &str = include_str!("../test/rsa2048-key.pem");
    const RSA_PUBLIC_KEY_DIGEST: &str = "efeda9bfead9fd0594f6a5cf6fdf6c16";
    const RSA_PUBLIC_KEY_MPDECIMAL: &str = "oponkjlpoknjpnafjepgkfmpgpnpgmbg";

    const EC256_PEM: &str = include_str!("../test/ec256-key.pem");
    const EC256_PUBLIC_KEY_DIGEST: &str = "edf2454ebdddf3ef647bfa8676c56c41";
    const EC256_PUBLIC_KEY_MPDECIMAL: &str = "onpcefeolnnnpdopgehlpkighgmfgmeb";

    fn decode_pem(pem: &str) -> SecretDocument {
        SecretDocument::from_pem(pem)
            .expect("Failed to decode ASN.1 DER document from PEM")
            .1
    }

    #[test]
    fn test_id_from_str() {
        // SHA256("")
        let digest = "e3b0c44298fc1c149afbf4c8996fb924".to_owned();
        let id = Id::from_str(&digest).unwrap();

        assert_eq!(format!("{}", id), "odlameecjipmbmbejkplpemijjgpljce");
    }

    #[test]
    fn test_id_from_rsa_public_key() {
        let secret_doc = decode_pem(RSA_PEM);
        let pkcs8_pki = PrivateKeyInfo::try_from(secret_doc.as_bytes()).unwrap();

        let rsa_private_key = RsaPrivateKey::try_from(pkcs8_pki.clone()).unwrap();
        let der_public_key = rsa_private_key.to_public_key().to_public_key_der().unwrap();

        // Create a Chrome extension ID from a ASN.1 DER encoded public key
        let id = Id::try_from(&der_public_key).unwrap();

        assert_eq!(format!("{}", id), RSA_PUBLIC_KEY_MPDECIMAL);
        assert_eq!(
            format!("{:?}", id),
            format!("Id({})", RSA_PUBLIC_KEY_DIGEST)
        );
    }

    #[test]
    fn test_id_from_ec_public_key() {
        let secret_doc = decode_pem(EC256_PEM);
        let pkcs8_pki = PrivateKeyInfo::try_from(secret_doc.as_bytes()).unwrap();

        let ecdsa_signing_key: EcdsaSigningKey<NistP256> =
            EcdsaSigningKey::try_from(pkcs8_pki.clone()).unwrap();

        let der_public_key = ecdsa_signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap();

        // Create a Chrome extension ID from a ASN.1 DER encoded public key
        let id = Id::try_from(&der_public_key).unwrap();

        assert_eq!(format!("{}", id), EC256_PUBLIC_KEY_MPDECIMAL);
        assert_eq!(
            format!("{:?}", id),
            format!("Id({})", EC256_PUBLIC_KEY_DIGEST)
        );
    }

    #[test]
    fn test_rsa_sign() {
        let secret_doc = decode_pem(RSA_PEM);

        let mut rng = rand::thread_rng();

        let id = Id::from_str(RSA_PUBLIC_KEY_DIGEST).unwrap();
        let crx = Crx::try_sign_with_rng(&mut rng, vec![secret_doc], ARCHIVE).unwrap();

        assert!(crx.verify().is_ok());
        assert_eq!(id, crx.id);
    }

    #[test]
    fn test_ecdsa_sign() {
        let secret_doc = decode_pem(EC256_PEM);

        let mut rng = rand::thread_rng();

        let id = Id::from_str(EC256_PUBLIC_KEY_DIGEST).unwrap();
        let crx = Crx::try_sign_with_rng(&mut rng, vec![secret_doc], ARCHIVE).unwrap();

        assert!(crx.verify().is_ok());
        assert_eq!(id, crx.id);
    }

    #[test]
    fn test_multi_sign() {
        let secret_doc1 = decode_pem(RSA_PEM);
        let secret_doc2 = decode_pem(EC256_PEM);

        let mut rng = rand::thread_rng();

        let id = Id::from_str(RSA_PUBLIC_KEY_DIGEST).unwrap();
        let crx =
            Crx::try_sign_with_rng(&mut rng, vec![secret_doc1, secret_doc2], ARCHIVE).unwrap();

        assert!(crx.verify().is_ok());
        assert_eq!(id, crx.id);
    }
}
