use std::{fmt, usize};

use age_core::format::{FileKey, Stanza};
use base64::prelude::{Engine, BASE64_STANDARD_NO_PAD};
use hpke::Deserializable;
use sha2::{Digest, Sha256};
use x509_cert::spki::SubjectPublicKeyInfoRef;
use yubikey::{piv::AlgorithmId, Certificate};

use crate::{
    key::Connection,
    native, p256,
    util::{base64_arg, MlKem768Extension},
    x25519, PLUGIN_NAME,
};

pub const TAG_BYTES: usize = 4;
pub const RECIPIENT_PREFIX: &str = "age1yubikey";
pub const TAGGED_RECIPIENT_PREFIX: &str = "age1tag";
pub const ENCRYPTED_FILE_KEY_BYTES: usize = 32;

#[derive(Debug)]
pub enum PublicKey {
    EccP256(p256::PublicKey),
    X25519(x25519::PublicKey),
    MlKemX25519(native::EncappedKey),
}

impl PublicKey {
    pub fn from_bytes(tag: &str, bytes: &[u8]) -> Option<Self> {
        match tag {
            x25519::STANZA_TAG => x25519::PublicKey::from_bytes(bytes).map(Self::X25519),
            native::STANZA_TAG => native::EncappedKey::from_bytes(bytes)
                .ok()
                .map(Self::MlKemX25519),
            p256::STANZA_TAG => p256::PublicKey::from_bytes(bytes).map(Self::EccP256),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::X25519(pk) => pk.as_bytes(),
            Self::EccP256(pk) => pk.as_bytes(),
            Self::MlKemX25519(pk) => pk.as_bytes(),
        }
    }

    pub fn decompress(&self) -> Option<Self> {
        match self {
            Self::EccP256(pk) => pk.decompress().map(Self::EccP256),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct EphemeralKeyBytes(PublicKey);

impl EphemeralKeyBytes {
    fn from_bytes(tag: &str, bytes: &[u8]) -> Option<Self> {
        match PublicKey::from_bytes(tag, bytes) {
            Some(pk) => Some(Self(pk)),
            _ => None,
        }
    }

    pub fn from_public_key(pk: PublicKey) -> Self {
        Self(pk)
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0.as_bytes()
    }

    pub fn algorithm(&self) -> AlgorithmId {
        match self.0 {
            PublicKey::EccP256(_) => AlgorithmId::EccP256,
            PublicKey::X25519(_) => AlgorithmId::X25519,
            PublicKey::MlKemX25519(_) => AlgorithmId::X25519,
        }
    }

    pub fn tag(&self) -> String {
        match self.0 {
            PublicKey::EccP256(_) => p256::STANZA_TAG.to_owned(),
            PublicKey::X25519(_) => x25519::STANZA_TAG.to_owned(),
            PublicKey::MlKemX25519(_) => native::STANZA_TAG.to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct RecipientLine {
    pub tag: [u8; TAG_BYTES],
    pub epk_bytes: EphemeralKeyBytes,
    pub encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl From<RecipientLine> for Stanza {
    fn from(r: RecipientLine) -> Self {
        Stanza {
            tag: r.epk_bytes.tag(),
            args: vec![
                BASE64_STANDARD_NO_PAD.encode(r.tag),
                BASE64_STANDARD_NO_PAD.encode(r.epk_bytes.as_bytes()),
            ],
            body: r.encrypted_file_key.to_vec(),
        }
    }
}

impl RecipientLine {
    pub(super) fn from_stanza(s: &Stanza) -> Option<Result<Self, ()>> {
        let algorithm = match s.tag.as_str() {
            p256::STANZA_TAG => Some(AlgorithmId::EccP256),
            x25519::STANZA_TAG => Some(AlgorithmId::X25519),
            _ => None,
        };
        if algorithm.is_none() && s.tag != native::STANZA_TAG {
            return None;
        }

        match algorithm {
            Some(AlgorithmId::X25519) => {
                let (tag, epk_bytes) = match &s.args[..] {
                    [tag, epk_bytes] => {
                        let base64_bytes = base64_arg(epk_bytes, [0; x25519::EPK_BYTES]).unwrap();
                        (
                            base64_arg(tag, [0; TAG_BYTES]),
                            EphemeralKeyBytes::from_bytes(&s.tag, &base64_bytes),
                        )
                    }
                    _ => (None, None),
                };

                Some(match (tag, epk_bytes, s.body[..].try_into()) {
                    (Some(tag), Some(epk_bytes), Ok(encrypted_file_key)) => Ok(RecipientLine {
                        tag,
                        epk_bytes,
                        encrypted_file_key,
                    }),
                    // Anything else indicates a structurally-invalid stanza.
                    _ => Err(()),
                })
            }
            Some(AlgorithmId::EccP256) => {
                let (tag, epk_bytes) = match &s.args[..] {
                    [tag, epk_bytes] => {
                        let base64_bytes = base64_arg(epk_bytes, [0; p256::EPK_BYTES]).unwrap();
                        (
                            base64_arg(tag, [0; TAG_BYTES]),
                            EphemeralKeyBytes::from_bytes(&s.tag, &base64_bytes),
                        )
                    }
                    _ => (None, None),
                };

                Some(match (tag, epk_bytes, s.body[..].try_into()) {
                    (Some(tag), Some(epk_bytes), Ok(encrypted_file_key)) => Ok(RecipientLine {
                        tag,
                        epk_bytes,
                        encrypted_file_key,
                    }),
                    // Anything else indicates a structurally-invalid stanza.
                    _ => Err(()),
                })
            }
            None => {
                let (tag, epk_bytes) = match &s.args[..] {
                    [tag, epk_bytes] => {
                        let base64_bytes = base64_arg(epk_bytes, [0; native::NENC]).unwrap();
                        (
                            base64_arg(tag, [0; TAG_BYTES]),
                            EphemeralKeyBytes::from_bytes(&s.tag, &base64_bytes),
                        )
                    }
                    _ => (None, None),
                };

                Some(match (tag, epk_bytes, s.body[..].try_into()) {
                    (Some(tag), Some(epk_bytes), Ok(encrypted_file_key)) => Ok(RecipientLine {
                        tag,
                        epk_bytes,
                        encrypted_file_key,
                    }),
                    // Anything else indicates a structurally-invalid stanza.
                    _ => Err(()),
                })
            }
            _ => None,
        }
    }
    pub fn unwrap_file_key(&self, conn: &mut Connection) -> Result<FileKey, ()> {
        conn.unwrap_file_key(self)
    }
}

#[derive(Clone, Debug)]
pub enum Recipient {
    EccP256(p256::Recipient),
    X25519(x25519::Recipient),
    MlKemX25519(native::Recipient),
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Recipient::EccP256(recipient) => recipient.fmt(f),
            Recipient::X25519(recipient) => recipient.fmt(f),
            Recipient::MlKemX25519(recipient) => recipient.fmt(f),
        }
    }
}

impl Recipient {
    /// Attempts to parse a supported YubiKey recipient.
    pub fn from_bytes(plugin_name: &str, bytes: &[u8]) -> Option<Self> {
        match plugin_name {
            PLUGIN_NAME => {
                if bytes.len() == 32 {
                    x25519::Recipient::from_bytes(bytes).map(Self::X25519)
                } else if bytes.len() > 1000 {
                    native::Recipient::from_bytes(bytes).map(Self::MlKemX25519)
                } else {
                    p256::Recipient::from_bytes(bytes).map(Self::EccP256)
                }
            }
            _ => None,
        }
    }

    pub fn from_spki(spki: SubjectPublicKeyInfoRef<'_>) -> Option<Self> {
        match spki.algorithm.oid {
            p256::OID_P256 => p256::Recipient::from_spki(spki).map(Self::EccP256),
            x25519::OID_X25519 => x25519::Recipient::from_spki(&spki).map(Self::X25519),
            _ => None,
        }
    }
    pub fn from_certificate(cert: &Certificate) -> Option<Self> {
        match cert.subject_pki().algorithm.oid {
            p256::OID_P256 => p256::Recipient::from_certificate(cert).map(Self::EccP256),
            x25519::OID_X25519 => {
                match cert
                    .cert
                    .tbs_certificate()
                    .get_extension::<MlKem768Extension>()
                    .expect("decode extension")
                {
                    Some(_) => native::Recipient::from_certificate(cert).map(Self::MlKemX25519),
                    None => x25519::Recipient::from_certificate(cert).map(Self::X25519),
                }
            }
            _ => None,
        }
    }

    pub fn to_encoded(&self) -> Option<Vec<u8>> {
        match self {
            Self::EccP256(recipient) => {
                let encoded_point = recipient.to_encoded();
                Some(encoded_point.as_bytes().to_owned())
            }
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::EccP256(_) => unimplemented!("EccP256 cannot serialize directly to bytes"),
            Self::X25519(recipient) => recipient.as_bytes(),
            Self::MlKemX25519(recipient) => recipient.as_bytes(),
        }
    }

    /// Returns the static tag for this recipient.
    pub fn static_tag(&self) -> [u8; TAG_BYTES] {
        match self {
            Recipient::EccP256(recipient) => recipient.tag(),
            Recipient::X25519(recipient) => recipient.tag(),
            Recipient::MlKemX25519(recipient) => static_tag(recipient.as_bytes()),
        }
    }

    pub fn wrap_file_key(&self, file_key: &FileKey) -> Stanza {
        match self {
            Recipient::EccP256(recipient) => recipient.wrap_file_key(file_key).into(),
            Recipient::X25519(recipient) => recipient.wrap_file_key(file_key).into(),
            Recipient::MlKemX25519(recipient) => recipient.wrap_file_key(file_key).into(),
        }
    }
}

pub fn static_tag(pk: &[u8]) -> [u8; TAG_BYTES] {
    Sha256::digest(pk)[0..TAG_BYTES]
        .try_into()
        .expect("length is correct")
}
