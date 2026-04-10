use age_core::{
    format::FileKey,
    primitives::{aead_encrypt, hkdf},
    secrecy::ExposeSecret,
};
use bech32::{ToBase32, Variant};
use sha2::{Digest, Sha256};
use x509_cert::spki::{ObjectIdentifier, SubjectPublicKeyInfoRef};
use yubikey::Certificate;

use std::fmt;

use crate::recipient::{
    EphemeralKeyBytes, RecipientLine, ENCRYPTED_FILE_KEY_BYTES, RECIPIENT_PREFIX, TAG_BYTES,
};

pub const EPK_BYTES: usize = 32;
pub const STANZA_TAG: &str = "piv-x25519";
pub const STANZA_KEY_LABEL: &[u8] = b"piv-x25519";
pub const OID_X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

#[derive(Clone, Debug)]
pub struct PublicKey(x25519_dalek::PublicKey);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let key_bytes: [u8; EPK_BYTES] = bytes.try_into().unwrap();
        match x25519_dalek::PublicKey::try_from(key_bytes) {
            Ok(pk) => Some(Self(pk)),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[derive(Clone)]
pub struct Recipient(x25519_dalek::PublicKey);

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
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let data: [u8; EPK_BYTES] = bytes.try_into().expect("correct key length");
        match x25519_dalek::PublicKey::try_from(data) {
            Ok(pubkey) => Some(Self(pubkey)),
            _ => None,
        }
    }

    pub fn from_certificate(cert: &Certificate) -> Option<Self> {
        Self::from_spki(&cert.subject_pki())
    }

    pub fn from_spki(spki: &SubjectPublicKeyInfoRef<'_>) -> Option<Self> {
        let pk_data: [u8; 32] = spki
            .subject_public_key
            .raw_bytes()
            .try_into()
            .expect("invalid spki");
        Some(Self(x25519_dalek::PublicKey::from(pk_data)))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn tag(&self) -> [u8; TAG_BYTES] {
        let tag = Sha256::digest(self.0.as_bytes());
        (&tag[0..TAG_BYTES]).try_into().expect("length is correct")
    }

    /// Exposes the wrapped public key.
    pub fn public_key(&self) -> &x25519_dalek::PublicKey {
        &self.0
    }

    pub fn wrap_file_key(&self, file_key: &FileKey) -> RecipientLine {
        let esk = x25519_dalek::EphemeralSecret::random();
        let epk = x25519_dalek::PublicKey::from(&esk);
        let epk_bytes =
            EphemeralKeyBytes::from_public_key(crate::recipient::PublicKey::X25519(PublicKey(epk)));

        let shared_secret = esk.diffie_hellman(self.public_key());

        let mut salt = vec![];
        salt.extend_from_slice(epk_bytes.as_bytes());
        salt.extend_from_slice(self.as_bytes());

        let enc_key = hkdf(
            &salt,
            crate::x25519::STANZA_KEY_LABEL,
            shared_secret.as_bytes(),
        );

        let encrypted_file_key = {
            let mut key = [0; ENCRYPTED_FILE_KEY_BYTES];
            key.copy_from_slice(&aead_encrypt(&enc_key, file_key.expose_secret()));
            key
        };

        RecipientLine {
            tag: self.tag(),
            epk_bytes,
            encrypted_file_key,
        }
    }
}
