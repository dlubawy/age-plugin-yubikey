use age_core::{format::FileKey, primitives::aead_encrypt, secrecy::ExposeSecret};
use bech32::{ToBase32, Variant};
use p256::{
    elliptic_curve::{
        common::Generate,
        sec1::{FromSec1Point, ToSec1Point},
    },
    pkcs8::SubjectPublicKeyInfoRef,
    Sec1Point,
};
use rand::rngs::SysRng;
use sha2::Sha256;
use x509_cert::spki::ObjectIdentifier;
use yubikey::Certificate;

use std::fmt;

use crate::recipient::{
    static_tag, EphemeralKeyBytes, RecipientLine, ENCRYPTED_FILE_KEY_BYTES, RECIPIENT_PREFIX,
    TAG_BYTES,
};

pub const EPK_BYTES: usize = 33;
pub const STANZA_TAG: &str = "piv-p256";
pub const STANZA_KEY_LABEL: &[u8] = b"piv-p256";
pub const OID_P256: ObjectIdentifier = p256::elliptic_curve::ALGORITHM_OID;

#[derive(Clone, Debug)]
pub struct PublicKey(Sec1Point);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let key_bytes: [u8; EPK_BYTES] = bytes.try_into().unwrap();
        let encoded = Sec1Point::from_bytes(key_bytes).ok()?;
        if encoded.is_compressed()
            && ::p256::PublicKey::from_sec1_point(&encoded)
                .is_some()
                .into()
        {
            Some(Self(encoded))
        } else {
            None
        }
    }

    pub fn decompress(&self) -> Option<Self> {
        let p = ::p256::PublicKey::from_sec1_point(&self.0).unwrap();
        Some(Self(p.to_sec1_point(false)))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Wrapper around a compressed secp256r1 curve point.
#[derive(Clone)]
pub struct Recipient(::p256::PublicKey);

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Recipient({:?})", self.to_encoded().as_bytes())
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            bech32::encode(
                RECIPIENT_PREFIX,
                self.to_encoded().as_bytes().to_base32(),
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
        let encoded = Sec1Point::from_bytes(bytes).ok()?;
        if encoded.is_compressed() {
            Self::from_encoded(&encoded)
        } else {
            None
        }
    }

    pub fn from_certificate(cert: &Certificate) -> Option<Self> {
        Self::from_spki(cert.subject_pki())
    }

    pub fn from_spki(spki: SubjectPublicKeyInfoRef<'_>) -> Option<Self> {
        // TODO: https://github.com/RustCrypto/formats/issues/1604
        ::p256::PublicKey::try_from(spki).ok().map(Recipient)
    }

    /// Attempts to parse a valid YubiKey recipient from its SEC-1 encoding.
    ///
    /// This accepts both compressed (as used by the plugin) and uncompressed (as used in
    /// the YubiKey certificate) encodings.
    fn from_encoded(encoded: &Sec1Point) -> Option<Self> {
        Option::from(::p256::PublicKey::from_sec1_point(encoded)).map(Recipient)
    }

    /// Returns the compressed SEC-1 encoding of this recipient.
    pub fn to_encoded(&self) -> Sec1Point {
        self.0.to_sec1_point(true)
    }

    pub fn tag(&self) -> [u8; TAG_BYTES] {
        static_tag(self.to_encoded().as_bytes())
    }

    /// Exposes the wrapped public key.
    pub fn public_key(&self) -> &::p256::PublicKey {
        &self.0
    }

    pub fn wrap_file_key(&self, file_key: &FileKey) -> RecipientLine {
        let esk =
            ::p256::ecdh::EphemeralSecret::try_generate_from_rng(&mut SysRng).expect("random key");
        let epk = esk.public_key().to_sec1_point(true);
        let epk_bytes = EphemeralKeyBytes::from_public_key(crate::recipient::PublicKey::EccP256(
            PublicKey(epk.into()),
        ));

        let shared_secret = esk.diffie_hellman(self.public_key());

        let mut salt = vec![];
        salt.extend_from_slice(epk_bytes.as_bytes());
        salt.extend_from_slice(self.to_encoded().as_bytes());

        let enc_key = {
            let mut okm = [0; 32];
            shared_secret
                .extract::<Sha256>(Some(&salt))
                .expand(crate::p256::STANZA_KEY_LABEL, &mut okm)
                .expect("okm is the correct length");
            okm
        };

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
