#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
//! This library provides generalized PKCS#8 support designed to work with a
//! number of different algorithms. It supports `no_std` platforms including
//! ones without a heap (albeit with reduced functionality).
//!
//! A CRX3 file consists of [header-size][header][archive].
//! [header] is an encoded protocol buffer and contains both a signed and
//! unsigned section. The unsigned section contains a set of key/signature pairs,
//! and the signed section is the encoding of another protocol buffer. All
//! signatures cover [prefix][signed-header-size][signed-header][archive].
//!
//! ## Example
//!
//! ```ignore
//! use crx::{Id, Keyset};
//! use pkcs8::{der::SecretDocument, PrivateKeyInfo};
//! use rand::thread_rng;
//! use std::fs;
//! use std::str::FromStr;
//!
//! // RSA or ECDSA private key .pem file contents
//! let pem = fs::read_to_string(...)?;
//!
//! let (_, secret_doc) = SecretDocument::from_pem(pem)?;
//!
//! let mut rng = thread_rng();
//!
//! let id = Id::from_str("e3b0c44298fc1c149afbf4c8996fb924")?;
//! let crx_keyset = Keyset::new(id, vec![secret_doc]);
//! let crx = crx_keyset.try_sign_with_rng(&mut rng, extension_zip_data)?;
//!
//! assert!(crx_keyset.verify(&crx).is_ok());
//! ```

use error::{Error, ErrorKind};
use std::{array::TryFromSliceError, io::Write, num::ParseIntError, str::FromStr};

use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY as EC, RSA_ENCRYPTION as RSA};
use core::fmt::{self, Debug};
use ecdsa::{Signature as EcdsaSignature, SigningKey as EcdsaSigningKey, VerifyingKey};
use p256::NistP256;
use pkcs8::{der::Document, DecodePublicKey, EncodePublicKey, PrivateKeyInfo, SecretDocument};
use prost::Message;
use rsa::{
    pkcs1v15::{Pkcs1v15Sign, SigningKey as Pkcs1v15SigningKey},
    PublicKey as _, RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};
use signature::{rand_core::CryptoRngCore, RandomizedSigner, Verifier};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

pub mod crx3 {
    include!(concat!(env!("OUT_DIR"), "/crx_file.rs"));
}
pub mod error;

/// The CRX id size.
pub const CRX_ID_SIZE: usize = 16;

// The CRX magic number (Cr24)
const CRX_MAGIC: &[u8; 4] = b"Cr24";

// The length of the CRX header section
const CRX_SIZE_HINT: usize = 4;

// The CRX header
const CRX_HEADER: &[u8; 16] = b"CRX3 SignedData\x00";

// The CRX version identifier
const CRX_VERSION: [u8; 4] = [3_u8, 0, 0, 0];

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
pub fn sign(archive: &[u8], pems: Vec<&str>) -> Vec<u8> {
    let (_, doc) = SecretDocument::from_pem(pem).map_err(|err| {
        println!("error 1");
        Error::from_pkcs8(err)
    })?;

    let pkcs8_pki = PrivateKeyInfo::try_from(doc.as_bytes()).map_err(|err| {
        println!("error 2");
        Error::from_pkcs8(err)
    })?;

    let signature = Keyset::new(Id::new(), vec![pkcs8_pki]);

    let mut rng = rand::thread_rng();

    signature.try_sign_with_rng(&mut rng, archive);
}

/// Chrome Web Extension format keyset.
#[derive(Clone)]
pub struct Keyset {
    id: Id,
    secret_docs: Vec<SecretDocument>,
}

impl Keyset {
    /// Create a new [`Keyset`].
    pub fn new(id: Id, secret_docs: Vec<SecretDocument>) -> Self {
        Self { id, secret_docs }
    }

    /// Sign the given archive and return a Chrome Web Extension file.
    pub fn try_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        archive: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let signed_data = crx3::SignedData {
            crx_id: Some(self.id.to_vec()),
        }
        .encode_to_vec();

        let crx_proof = create_proof(archive, &signed_data)?;

        let mut rsa_key_proofs = Vec::with_capacity(0);
        let mut ecdsa_key_proofs = Vec::with_capacity(0);

        self.secret_docs
            .to_owned()
            .into_iter()
            .try_for_each(|secret_doc| {
                let pkcs8_pki =
                    PrivateKeyInfo::try_from(secret_doc.as_bytes()).map_err(Error::from_pkcs8)?;
                match pkcs8_pki.algorithm.oid {
                    RSA => {
                        let rsa_private_key = RsaPrivateKey::try_from(pkcs8_pki.clone())
                            .map_err(Error::from_pkcs8)?;
                        let der_public_key = rsa_private_key
                            .to_public_key()
                            .to_public_key_der()
                            .map_err(Error::from_pkcs8)?;

                        let rsa_signing_key =
                            Pkcs1v15SigningKey::<Sha256>::new_with_prefix(rsa_private_key);
                        let rsa_signature = rsa_signing_key.sign_with_rng(rng, &crx_proof);

                        rsa_key_proofs.push((der_public_key, rsa_signature.as_ref().to_vec()));

                        Ok(())
                    }
                    EC => {
                        let ecdsa_signing_key: EcdsaSigningKey<NistP256> =
                            EcdsaSigningKey::try_from(pkcs8_pki.clone())
                                .map_err(Error::from_pkcs8)?;

                        let ecdsa_signature: EcdsaSignature<NistP256> = ecdsa_signing_key
                            .try_sign_with_rng(rng, &crx_proof)
                            .map_err(Error::from_pkcs8)?;

                        let der_public_key = ecdsa_signing_key
                            .verifying_key()
                            .to_public_key_der()
                            .map_err(Error::from_pkcs8)?;

                        ecdsa_key_proofs
                            .push((der_public_key, ecdsa_signature.to_der().as_bytes().to_vec()));

                        Ok(())
                    }
                    _ => Err(Box::new(Error::from_crx(format!(
                        "Invalid private key algorithm: {:?}",
                        pkcs8_pki.algorithm.oid.as_bytes()
                    )))),
                }
            })?;

        // CRX header containing the asymmetric key proof
        let crx_file_header = crx3::CrxFileHeader {
            sha256_with_rsa: rsa_key_proofs
                .iter()
                .map(|(public_key, signature)| crx3::AsymmetricKeyProof {
                    public_key: Some(public_key.to_owned().into_vec()),
                    signature: Some(signature.to_owned()),
                })
                .collect(),
            sha256_with_ecdsa: ecdsa_key_proofs
                .iter()
                .map(|(public_key, signature)| crx3::AsymmetricKeyProof {
                    public_key: Some(public_key.to_owned().into_vec()),
                    signature: Some(signature.to_owned()),
                })
                .collect(),
            signed_header_data: Some(signed_data),
        }
        .encode_to_vec();

        let mut crx = Vec::with_capacity(
            CRX_MAGIC.len()
                + CRX_VERSION.len()
                + CRX_SIZE_HINT
                + crx_file_header.len()
                + archive.len(),
        );

        crx.write_all(CRX_MAGIC)?;
        crx.write_all(&CRX_VERSION)?;

        let crx_file_header_size_hint: [u8; CRX_SIZE_HINT] =
            u32::to_le_bytes(crx_file_header.len() as u32);
        crx.write_all(&crx_file_header_size_hint)?;

        crx.write_all(&crx_file_header)?;
        crx.write_all(archive)?;

        Ok(crx)
    }

    /// Verify a Chrome Web Extension file.
    pub fn verify(&self, crx: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if crx.len() < CRX_MAGIC.len() + CRX_VERSION.len() + CRX_SIZE_HINT {
            return Err(Box::new(Error::from_crx("Buffer too small".to_string())));
        }

        // Try to parse the crx signature
        let crx_magic = &crx[0..CRX_MAGIC.len()];
        if crx_magic != CRX_MAGIC {
            return Err(Box::new(match std::str::from_utf8(crx_magic) {
                Ok(v) => Error::from_crx(format!(
                    "Invalid crx magic number. Expected {} but got {}",
                    std::str::from_utf8(CRX_MAGIC)
                        .expect("Failed to convert CRX magic number to utf-8"),
                    v
                )),
                Err(err) => Error::from_crx(format!("Invalid CRX magic number. {:?}", err)),
            }));
        }

        let offset = CRX_MAGIC.len();
        let crx_version = &crx[offset..offset + CRX_VERSION.len()];
        if crx_version != CRX_VERSION {
            return Err(Box::new(Error::from_crx("Invalid CRX version".to_string())));
        }

        let offset = offset + CRX_VERSION.len();

        let crx_header_length =
            u32::from_le_bytes(crx[offset..offset + CRX_SIZE_HINT].try_into().unwrap());
        if crx_header_length == 0 {
            return Err(Box::new(Error::from_crx(
                "Invalid CRX header length".to_string(),
            )));
        }

        let offset = offset + CRX_SIZE_HINT;
        let crx_file_header =
            crx3::CrxFileHeader::decode(&crx[offset..offset + crx_header_length as usize])
                .map_err(|err| {
                    Error::from_crx(format!("Failed to decode `crx3::CrxFileHeader` {:?}", err))
                })?;

        if crx_file_header.sha256_with_rsa.is_empty()
            && crx_file_header.sha256_with_ecdsa.is_empty()
        {
            return Err(Box::new(Error::from_crx(
                "No asymmetric key proofs found".to_string(),
            )));
        }

        let signed_data = if let Some(signed_data) = crx_file_header.signed_header_data.clone() {
            signed_data
        } else {
            return Err(Box::new(Error::from_crx(
                "Missing crx signed header data".to_string(),
            )));
        };

        let crx_signed_data = crx3::SignedData::decode(signed_data.as_slice()).map_err(|err| {
            Error::from_crx(format!("Failed to decode `crx3::SignedData`: {:?}", err))
        })?;

        let id = if let Some(crx_id) = crx_signed_data.crx_id {
            if crx_id.len() != CRX_ID_SIZE {
                return Err(Box::new(Error::from_crx("Invalid CRX id size".to_string())));
            }

            Id::try_from(crx_id)?
        } else {
            return Err(Box::new(Error::from_crx(
                "Required proof missing".to_string(),
            )));
        };

        let offset = offset + crx_header_length as usize;
        let archive = &crx[offset..crx.len()];

        let crx_proof = create_proof(archive, &signed_data)?;

        if !crx_file_header.sha256_with_rsa.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(&crx_proof);
            let digest = hasher.finalize();

            crx_file_header.sha256_with_rsa.into_iter().try_for_each(|key_proof| {
                let rsa_public_key = RsaPublicKey::from_public_key_der(key_proof.public_key()).map_err(|err| {
                    Error::from_crx(format!("Failed to deserialize RSA public key from ASN.1 DER-encoded public key: {:?}", err))
                })?;

                rsa_public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, key_proof.signature()).map_err(|err| {
                    Error::from_crx(format!("Failed to verify RSA signature: {:?}", err))
                })
            })?;
        }

        if !crx_file_header.sha256_with_ecdsa.is_empty() {
            crx_file_header.sha256_with_ecdsa.into_iter().try_for_each(|key_proof| {
                let ecdsa_verifying_key = VerifyingKey::<NistP256>::from_public_key_der(key_proof.public_key()).map_err(|err| {
                    Error::from_crx(format!("Failed to deserialize ECDSA verifying key using the NIST P-256 curve from ASN.1 DER-encoded public key: {:?}", err))
                })?;

                let ecdsa_signature = EcdsaSignature::<NistP256>::from_der(key_proof.signature()).map_err(|err| {
                    Error::from_crx(format!("Failed to deserialize ECDSA (NIST P-256) signature from ASN.1 DER-encoded public key: {:?}", err))
                })?;

                ecdsa_verifying_key.verify(&crx_proof, &ecdsa_signature).map_err(|err| {
                    Error::from_crx(format!("Failed to verify ECDSA (NIST P-256) signature: {:?}", err))
                })
            })?;
        }

        Ok(())
    }
}

impl Debug for Keyset {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Keyset")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

fn create_proof(archive: &[u8], crx_signed_data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut buf = Vec::with_capacity(
        CRX_HEADER.len() + CRX_SIZE_HINT + crx_signed_data.len() + archive.len(),
    );
    buf.write_all(CRX_HEADER)?;

    let crx_signed_data_size_hint: [u8; CRX_SIZE_HINT] =
        u32::to_le_bytes(crx_signed_data.len() as u32);
    buf.write_all(&crx_signed_data_size_hint)?;

    buf.write_all(crx_signed_data)?;
    buf.write_all(archive)?;

    Ok(buf)
}

/// Chrome Web Extension ID.
///
/// # Examples
///
/// ```
/// use crx::Id;
/// use std::num::ParseIntError;
/// use std::str::FromStr;
///
/// fn main() -> Result<(), ParseIntError> {
///     // The sha256 digest of an ASN.1 DER-encoded public key
///     let digest = "e3b0c44298fc1c149afbf4c8996fb924".to_string();
///     let id = Id::from_str(&digest)?;
///
///     assert_eq!(format!("{}", id), "odlameecjipmbmbejkplpemijjgpljce");
///
///     Ok(())
/// }
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

    /// Convert this `Id` into a new `Vec`.
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl FromStr for Id {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            bytes: (0..s.len())
                .take(CRX_ID_SIZE * 2)
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
                .collect::<Result<Vec<u8>, ParseIntError>>()?
                .as_slice()
                .try_into()
                .expect("Failed to create sized slice"),
        })
    }
}

impl TryFrom<&Document> for Id {
    type Error = TryFromSliceError;

    fn try_from(der: &Document) -> Result<Self, Self::Error> {
        let mut hasher = Sha256::new();
        hasher.update(der.clone());

        Ok(Self {
            bytes: hasher.finalize()[0..CRX_ID_SIZE].try_into()?,
        })
    }
}

impl TryFrom<Vec<u8>> for Id {
    type Error = TryFromSliceError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: bytes.as_slice().try_into()?,
        })
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            f.write_str(
                &char::from_u32(97 + ((byte >> 4) & 0xf) as u32)
                    .unwrap()
                    .to_string(),
            )?;
            f.write_str(
                &char::from_u32((97 + (byte & 0xf)) as u32)
                    .unwrap()
                    .to_string(),
            )?;
        }

        Ok(())
    }
}

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

    const RSA_PEM: &str = include_str!("../test/rsa.pem");
    const RSA_PUBLIC_KEY_DIGEST: &str = "efeda9bfead9fd0594f6a5cf6fdf6c16";
    const ECDSA_PEM: &str = include_str!("../test/ecdsa.pem");
    const ECDSA_PUBLIC_KEY_DIGEST: &str = "edf2454ebdddf3ef647bfa8676c56c41";

    fn decode_pem(pem: &str) -> SecretDocument {
        SecretDocument::from_pem(pem)
            .expect("Failed to decode ASN.1 DER document from PEM")
            .1
    }

    #[test]
    fn test_id_from_str() {
        // SHA256("")
        let digest = "e3b0c44298fc1c149afbf4c8996fb924".to_string();
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

        assert_eq!(
            format!("{:?}", id),
            format!("Id({})", RSA_PUBLIC_KEY_DIGEST)
        );
    }

    #[test]
    fn test_id_from_ecdsa_public_key() {
        let secret_doc = decode_pem(ECDSA_PEM);
        let pkcs8_pki = PrivateKeyInfo::try_from(secret_doc.as_bytes()).unwrap();

        let ecdsa_signing_key: EcdsaSigningKey<NistP256> =
            EcdsaSigningKey::try_from(pkcs8_pki.clone()).unwrap();

        let der_public_key = ecdsa_signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap();

        // Create a Chrome extension ID from a ASN.1 DER encoded public key
        let id = Id::try_from(&der_public_key).unwrap();

        assert_eq!(
            format!("{:?}", id),
            format!("Id({})", ECDSA_PUBLIC_KEY_DIGEST)
        );
    }

    #[test]
    fn test_rsa_sign() {
        let secret_doc = decode_pem(RSA_PEM);

        let mut rng = rand::thread_rng();

        let id = Id::from_str(RSA_PUBLIC_KEY_DIGEST).unwrap();
        let crx_keyset = Keyset::new(id, vec![secret_doc]);
        let crx = crx_keyset.try_sign_with_rng(&mut rng, ARCHIVE).unwrap();

        crx_keyset.verify(&crx).unwrap();
    }

    #[test]
    fn test_ecdsa_sign() {
        let secret_doc = decode_pem(ECDSA_PEM);

        let mut rng = rand::thread_rng();

        let id = Id::from_str(ECDSA_PUBLIC_KEY_DIGEST).unwrap();
        let crx_keyset = Keyset::new(id, vec![secret_doc]);
        let crx = crx_keyset.try_sign_with_rng(&mut rng, ARCHIVE).unwrap();

        crx_keyset.verify(&crx).unwrap();
    }

    #[test]
    fn test_multi_sign() {
        let secret_doc1 = decode_pem(RSA_PEM);
        let secret_doc2 = decode_pem(ECDSA_PEM);

        let mut rng = rand::thread_rng();

        let id = Id::from_str(RSA_PUBLIC_KEY_DIGEST).unwrap();
        let crx_keyset = Keyset::new(id, vec![secret_doc1, secret_doc2]);
        let crx = crx_keyset.try_sign_with_rng(&mut rng, ARCHIVE).unwrap();

        crx_keyset.verify(&crx).unwrap();
    }
}
