use bech32::{ToBase32, Variant};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;
use yubikey::{certificate::PublicKeyInfo, Certificate};

use std::fmt;

use crate::RECIPIENT_PREFIX;

pub(crate) const EPK_BYTES: usize = 32;
pub(crate) const TAG_BYTES: usize = 4;
pub(crate) const STANZA_TAG: &str = "X25519";

pub(crate) const STANZA_KEY_LABEL: &[u8] = b"age-encryption.org/v1/X25519";

#[derive(Clone)]
pub struct Recipient(PublicKey);

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Recipient({:?})", self)
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            bech32::encode(
                RECIPIENT_PREFIX,
                self.0.as_bytes().to_base32(),
                Variant::Bech32,
            )
            .expect("HRP is valid")
            .as_str(),
        )
    }
}

impl Recipient {
    /// Attempts to parse a valid YubiKey recipient from its compressed SEC-1 byte encoding.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let data: [u8; EPK_BYTES] = bytes.try_into().unwrap();
        match PublicKey::try_from(data) {
            Ok(pubkey) => Some(Self(pubkey)),
            _ => None,
        }
    }

    pub(crate) fn from_certificate(cert: &Certificate) -> Option<Self> {
        Self::from_spki(cert.subject_pki())
    }

    pub(crate) fn from_spki(spki: &PublicKeyInfo) -> Option<Self> {
        match spki {
            PublicKeyInfo::X25519(pubkey) => Some(Self(*pubkey)),
            _ => None,
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub(crate) fn tag(&self) -> [u8; TAG_BYTES] {
        let tag = Sha256::digest(self.0.as_bytes());
        (&tag[0..TAG_BYTES]).try_into().expect("length is correct")
    }

    /// Exposes the wrapped public key.
    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.0
    }
}
