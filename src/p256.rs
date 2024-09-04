use age_core::{format::FileKey, primitives::aead_encrypt, secrecy::ExposeSecret};
use bech32::{ToBase32, Variant};
use p256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    pkcs8::SubjectPublicKeyInfoRef,
    EncodedPoint,
};
use rand_core::OsRng;
use sha2::Sha256;
use x509_cert::spki::ObjectIdentifier;
use yubikey::Certificate;

use std::fmt;

use crate::{
    recipient::{static_tag, EphemeralKeyBytes, ENCRYPTED_FILE_KEY_BYTES, TAG_BYTES},
    RecipientLine, RECIPIENT_PREFIX,
};

pub(crate) const EPK_BYTES: usize = 33;
pub(crate) const STANZA_TAG: &str = "piv-p256";
pub(crate) const STANZA_KEY_LABEL: &[u8] = b"piv-p256";
pub(crate) const OID_P256: ObjectIdentifier = p256::elliptic_curve::ALGORITHM_OID;

#[derive(Clone, Debug)]
pub struct PublicKey(EncodedPoint);

impl PublicKey {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let key_bytes: [u8; EPK_BYTES] = bytes.try_into().unwrap();
        let encoded = EncodedPoint::from_bytes(key_bytes).ok()?;
        if encoded.is_compressed()
            && ::p256::PublicKey::from_encoded_point(&encoded)
                .is_some()
                .into()
        {
            Some(Self(encoded))
        } else {
            None
        }
    }

    pub(crate) fn decompress(&self) -> Option<Self> {
        let p = ::p256::PublicKey::from_encoded_point(&self.0).unwrap();
        Some(Self(p.to_encoded_point(false)))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
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
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let encoded = EncodedPoint::from_bytes(bytes).ok()?;
        if encoded.is_compressed() {
            Self::from_encoded(&encoded)
        } else {
            None
        }
    }

    pub(crate) fn from_certificate(cert: &Certificate) -> Option<Self> {
        Self::from_spki(cert.subject_pki())
    }

    pub(crate) fn from_spki(spki: SubjectPublicKeyInfoRef<'_>) -> Option<Self> {
        // TODO: https://github.com/RustCrypto/formats/issues/1604
        ::p256::PublicKey::try_from(spki).ok().map(Recipient)
    }

    /// Attempts to parse a valid YubiKey recipient from its SEC-1 encoding.
    ///
    /// This accepts both compressed (as used by the plugin) and uncompressed (as used in
    /// the YubiKey certificate) encodings.
    fn from_encoded(encoded: &EncodedPoint) -> Option<Self> {
        Option::from(::p256::PublicKey::from_encoded_point(encoded)).map(Recipient)
    }

    /// Returns the compressed SEC-1 encoding of this recipient.
    pub(crate) fn to_encoded(&self) -> EncodedPoint {
        self.0.to_encoded_point(true)
    }

    pub(crate) fn tag(&self) -> [u8; TAG_BYTES] {
        static_tag(self.to_encoded().as_bytes())
    }

    /// Exposes the wrapped public key.
    pub(crate) fn public_key(&self) -> &::p256::PublicKey {
        &self.0
    }

    pub(crate) fn wrap_file_key(&self, file_key: &FileKey) -> RecipientLine {
        let esk = ::p256::ecdh::EphemeralSecret::try_from_rng(&mut OsRng).expect("random key");
        let epk = esk.public_key().to_encoded_point(true);
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
