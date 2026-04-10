use age_core::{format::FileKey, primitives::hkdf, secrecy::ExposeSecret};
use bech32::{ToBase32, Variant};
use hpke::{Deserializable, Kem as KemTrait, Serializable};
use ml_kem::{kem::Decapsulate, ml_kem_768, Encapsulate, FromSeed, KeyExport, KeyInit, TryKeyInit};
use sha2::{Digest, Sha256};
use sha3::{
    digest::{Digest as Sha3Digest, ExtendableOutput, FixedOutput, Update, XofReader},
    Sha3_256, Shake256,
};
use typenum::{UInt, UTerm, Unsigned, B0, B1, U32};
use x509_cert::spki::SubjectPublicKeyInfoRef;
use yubikey::Certificate;

use std::fmt;

use crate::{
    recipient::{EphemeralKeyBytes, RecipientLine, TAG_BYTES},
    util::MlKem768Extension,
};

// KEM Parameters
pub const NENC: usize = 1120;
pub const NPK: usize = 1216;
pub const NSK: usize = 32;
pub const KEM_NCT: usize = 1088;
pub const KEM_NEK: usize = 1184;
pub const KEM_NSEED: usize = 64;
pub const GROUP_NELEM: usize = 32;
pub const GROUP_NSEED: usize = 32;

pub const STANZA_TAG: &str = "mlkem768x25519tag";
pub const STANZA_KEY_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519tag";
pub const LABEL: &[u8] = b"MLKEM768-X25519";
pub const RECIPIENT_PREFIX: &str = "age1tagpq";

fn stanza_tag(ikm: &[u8], salt: &str) -> [u8; 4] {
    let tag: [u8; 32] = hkdf(salt.as_bytes(), "".as_bytes(), ikm);
    tag[..4].try_into().expect("correct length")
}

fn hpke_seal<R: hpke::rand_core::CryptoRng + hpke::rand_core::Rng>(
    pk_recip: &<Kem as KemTrait>::PublicKey,
    info: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> (EncappedKey, Vec<u8>) {
    hpke::single_shot_seal::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, Kem, R>(
        &hpke::OpModeS::Base,
        pk_recip,
        info,
        plaintext,
        &[],
        rng,
    )
    .expect("no errors should occur with these HPKE parameters")
}

#[derive(Clone, Debug)]
pub struct PublicKey(
    [u8; NPK],
    ml_kem_768::EncapsulationKey,
    x25519_dalek::PublicKey,
);

impl PublicKey {
    pub fn from(ek_pq: ml_kem_768::EncapsulationKey, ek_t: x25519_dalek::PublicKey) -> Self {
        let mut ek_bytes: [u8; NPK] = [0; NPK];
        ek_bytes[..KEM_NEK].copy_from_slice(&ek_pq.to_bytes());
        ek_bytes[KEM_NEK..].copy_from_slice(&ek_t.to_bytes());
        Self(ek_bytes, ek_pq, ek_t)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..NPK]
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for PublicKey {}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        let ek_pq =
            ml_kem_768::EncapsulationKey::new_from_slice(&encoded[..KEM_NEK]).map_err(|_| {
                hpke::HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
            })?;
        let ek_t_bytes: [u8; GROUP_NELEM] = encoded[KEM_NEK..].try_into().unwrap();
        let ek_t = x25519_dalek::PublicKey::try_from(ek_t_bytes).map_err(|_| {
            hpke::HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
        })?;
        Ok(PublicKey::from(ek_pq, ek_t))
    }
}

impl Serializable for PublicKey {
    type OutputSize = UInt<
        UInt<
            UInt<
                UInt<
                    UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B1>, B1>, B0>, B0>,
                    B0,
                >,
                B0,
            >,
            B0,
        >,
        B0,
    >;
    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0);
    }
}

#[derive(Clone)]
pub struct PrivateKey(
    [u8; NSK],
    ml_kem_768::DecapsulationKey,
    x25519_dalek::StaticSecret,
);

impl PrivateKey {
    pub fn from(
        seed: [u8; NSK],
        dk_pq: ml_kem_768::DecapsulationKey,
        dk_t: x25519_dalek::StaticSecret,
    ) -> Self {
        Self(seed, dk_pq, dk_t)
    }

    pub fn seed(&self) -> [u8; NSK] {
        self.0
    }

    pub fn to_public_key(&self) -> PublicKey {
        let expanded_key = ExpandedKey::from(&self.0);
        let mut kem_public_key: [u8; NPK] = [0; NPK];
        kem_public_key[..KEM_NEK].copy_from_slice(&expanded_key.ek_pq.to_bytes()[..KEM_NEK]);
        kem_public_key[KEM_NEK..].copy_from_slice(&expanded_key.ek_t.as_bytes()[..GROUP_NELEM]);
        PublicKey(kem_public_key, expanded_key.ek_pq, expanded_key.ek_t)
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for PrivateKey {}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        let dk_pq =
            ml_kem_768::DecapsulationKey::new_from_slice(&encoded[..KEM_NCT]).map_err(|_| {
                hpke::HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
            })?;
        let dk_t_bytes: [u8; GROUP_NELEM] = encoded[KEM_NCT..].try_into().map_err(|_| {
            hpke::HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
        })?;
        let dk_t = x25519_dalek::StaticSecret::from(dk_t_bytes);
        let private_key: [u8; NSK] = encoded.try_into().map_err(|_| {
            hpke::HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
        })?;
        Ok(Self(private_key, dk_pq, dk_t))
    }
}

impl Serializable for PrivateKey {
    type OutputSize = U32;
    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0);
    }
}

#[derive(Clone, Debug)]
pub struct EncappedKey([u8; NENC]);

impl EncappedKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..NENC]
    }
}

impl Deserializable for EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        let encapped_key: [u8; NENC] = encoded.try_into().map_err(|_| {
            hpke::HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
        })?;
        Ok(Self(encapped_key))
    }
}

impl Serializable for EncappedKey {
    type OutputSize = UInt<
        UInt<
            UInt<
                UInt<
                    UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B1>, B1>, B0>,
                    B0,
                >,
                B0,
            >,
            B0,
        >,
        B0,
    >;
    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0);
    }
}

struct ExpandedKey {
    ek_pq: ml_kem_768::EncapsulationKey,
    dk_pq: ml_kem_768::DecapsulationKey,
    ek_t: x25519_dalek::PublicKey,
    dk_t: x25519_dalek::StaticSecret,
}

impl ExpandedKey {
    fn from(seed: &[u8; NSK]) -> Self {
        let mut seed_bytes_pq = [0; KEM_NSEED];
        let mut seed_bytes_t = [0; GROUP_NSEED];
        let mut xof = sha3::Shake256::default().chain(seed).finalize_xof();
        xof.read(&mut seed_bytes_pq);
        xof.read(&mut seed_bytes_t);

        let seed_pq = ml_kem::Seed::try_from(seed_bytes_pq).unwrap();
        let (dk_pq, ek_pq) = ml_kem::MlKem768::from_seed(&seed_pq);

        let dk_t = x25519_dalek::StaticSecret::from(seed_bytes_t);
        let ek_t = x25519_dalek::PublicKey::from(&dk_t);

        Self {
            ek_pq,
            dk_pq,
            ek_t,
            dk_t,
        }
    }
}

#[derive(Clone)]
pub struct Kem {
    pub ek: PublicKey,
    pub dk: PrivateKey,
}

impl Kem {
    pub fn new() -> Kem {
        let mut csprng = rand::rng();
        let (dk, ek) = Kem::gen_keypair(&mut csprng);
        Self { ek, dk }
    }

    pub fn try_from_certificate(cert: &Certificate) -> Result<Self, hpke::HpkeError> {
        match cert
            .cert
            .tbs_certificate()
            .get_extension::<MlKem768Extension>()
            .expect("decode extension")
        {
            Some((_, ext)) => {
                let seed = ext.as_bytes();
                let expanded_key = ExpandedKey::from(seed);
                let ek_t_data: [u8; 32] = cert
                    .subject_pki()
                    .subject_public_key
                    .raw_bytes()
                    .try_into()
                    .expect("invalid spki");
                let ek_t = x25519_dalek::PublicKey::from(ek_t_data);
                let ek = PublicKey::from(expanded_key.ek_pq, ek_t);
                let dk = PrivateKey::from(*seed, expanded_key.dk_pq, expanded_key.dk_t);
                Ok(Self { ek, dk })
            }
            _ => Err(hpke::HpkeError::InvalidPskBundle),
        }
    }

    pub fn from(seed: &[u8; NSK]) -> Self {
        let expanded_key = ExpandedKey::from(seed);
        let dk = PrivateKey(*seed, expanded_key.dk_pq, expanded_key.dk_t);
        let ek = dk.to_public_key();
        Self { ek, dk }
    }
}

impl KemTrait for Kem {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncappedKey = EncappedKey;
    type NSecret = U32;

    const KEM_ID: u16 = 0x647a;

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
        sk.to_public_key()
    }

    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let mut seed: [u8; NSK] = [0; NSK];
        Shake256::default()
            .chain(&ikm)
            .chain(b"HPKE-v1")
            .chain(b"KEM")
            .chain(Self::KEM_ID.to_be_bytes())
            .chain(
                u16::try_from(b"DeriveKeyPair".len())
                    .expect("short enough")
                    .to_be_bytes(),
            )
            .chain(b"DeriveKeyPair")
            .chain(u16::try_from(NSK).expect("short enough").to_be_bytes())
            .chain(b"")
            .finalize_xof_into(&mut seed);

        let expanded_key = ExpandedKey::from(&seed);
        let dk = PrivateKey(seed, expanded_key.dk_pq, expanded_key.dk_t);
        let ek = dk.to_public_key();
        (dk, ek)
    }

    fn gen_keypair<R: rand::CryptoRng + rand::Rng>(
        csprng: &mut R,
    ) -> (Self::PrivateKey, Self::PublicKey) {
        let mut seed: [u8; NSK] = [0; NSK];
        csprng
            .try_fill_bytes(&mut seed)
            .expect("seed of proper length");
        let expanded_key = ExpandedKey::from(&seed);
        let dk = PrivateKey(seed, expanded_key.dk_pq, expanded_key.dk_t);
        let ek = dk.to_public_key();
        (dk, ek)
    }

    fn decap(
        sk_recip: &Self::PrivateKey,
        _pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<hpke::kem::SharedSecret<Self>, hpke::HpkeError> {
        let encapped_key_bytes = encapped_key.to_bytes();
        let mut ct_pq_bytes: [u8; KEM_NCT] = [0; KEM_NCT];
        ct_pq_bytes[..KEM_NCT].copy_from_slice(&encapped_key_bytes[..KEM_NCT]);
        let ct_pq: ml_kem::Ciphertext<ml_kem::MlKem768> = ct_pq_bytes.into();
        let mut ct_t: [u8; GROUP_NELEM] = [0; GROUP_NELEM];
        ct_t[..GROUP_NELEM].copy_from_slice(&encapped_key_bytes[KEM_NCT..]);

        let sk_bytes: [u8; NSK] = sk_recip.to_bytes().try_into().unwrap();
        let expanded_key = ExpandedKey::from(&sk_bytes);

        let ss_pq = expanded_key.dk_pq.decapsulate(&ct_pq);
        // TODO: switch to yubikey DH
        let ss_t = x25519_dalek::x25519(ct_t, expanded_key.dk_t.as_bytes().to_owned());

        let mut ss_hash = Sha3_256::default();
        Sha3Digest::update(&mut ss_hash, &ss_pq);
        Sha3Digest::update(&mut ss_hash, &ss_t);
        Sha3Digest::update(&mut ss_hash, &ct_t);
        Sha3Digest::update(&mut ss_hash, expanded_key.ek_t.as_bytes());
        Sha3Digest::update(&mut ss_hash, LABEL);
        let ss = hpke::kem::SharedSecret(ss_hash.finalize_fixed());
        Ok(ss)
    }

    fn encap<R: rand::rand_core::CryptoRng + rand::rand_core::Rng>(
        pk_recip: &Self::PublicKey,
        _sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(hpke::kem::SharedSecret<Self>, Self::EncappedKey), hpke::HpkeError> {
        let pk_bytes = pk_recip.to_bytes();

        let ek_pq = ml_kem_768::EncapsulationKey::new_from_slice(&pk_bytes[..KEM_NEK]).unwrap();

        let mut ek_t_bytes: [u8; GROUP_NELEM] = [0; GROUP_NELEM];
        ek_t_bytes[..GROUP_NELEM].copy_from_slice(&pk_bytes[KEM_NEK..]);
        let ek_t = x25519_dalek::PublicKey::from(ek_t_bytes);

        let (ct_pq, ss_pq) = ek_pq.encapsulate_with_rng(csprng);

        let sk_e = x25519_dalek::EphemeralSecret::random_from_rng(csprng);
        let ct_t = x25519_dalek::PublicKey::from(&sk_e);
        let ss_t = sk_e.diffie_hellman(&ek_t);

        let mut ss_hash = Sha3_256::default();
        Sha3Digest::update(&mut ss_hash, &ss_pq);
        Sha3Digest::update(&mut ss_hash, ss_t.as_bytes());
        Sha3Digest::update(&mut ss_hash, ct_t.as_bytes());
        Sha3Digest::update(&mut ss_hash, ek_t.as_bytes());
        Sha3Digest::update(&mut ss_hash, LABEL);
        let ss = hpke::kem::SharedSecret(ss_hash.finalize_fixed());

        let mut ct: [u8; NENC] = [0; NENC];
        ct[..KEM_NCT].copy_from_slice(&ct_pq);
        ct[KEM_NCT..].copy_from_slice(&ct_t.as_bytes()[..GROUP_NELEM]);
        let ek = Self::EncappedKey::from_bytes(&ct[..NENC])?;

        Ok((ss, ek))
    }
}

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
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut data: [u8; NPK] = [0; NPK];
        data[..NPK].copy_from_slice(&bytes[..NPK]);
        match PublicKey::from_bytes(&data) {
            Ok(pubkey) => Some(Self(pubkey)),
            _ => None,
        }
    }

    pub fn from_certificate(cert: &Certificate) -> Option<Self> {
        match cert
            .cert
            .tbs_certificate()
            .get_extension::<MlKem768Extension>()
            .expect("decode extension")
        {
            Some((_, ext)) => {
                let kem_key = Kem::from(ext.as_bytes());
                Some(Self(kem_key.ek))
            }
            _ => None,
        }
    }

    pub fn from_spki(spki: &SubjectPublicKeyInfoRef<'_>) -> Option<Self> {
        let pk_data: [u8; NPK] = spki
            .subject_public_key
            .raw_bytes()
            .try_into()
            .expect("invalid spki");
        match PublicKey::from_bytes(&pk_data) {
            Ok(pk) => Some(Self(pk)),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn tag(&self, enc: &EncappedKey) -> [u8; TAG_BYTES] {
        let encoded_pk = Sha256::digest(self.0.as_bytes());
        let mut ikm: [u8; NENC + TAG_BYTES] = [0; NENC + TAG_BYTES];
        ikm[..NENC].copy_from_slice(&enc.as_bytes()[..NENC]);
        ikm[NENC..].copy_from_slice(&encoded_pk[..TAG_BYTES]);
        hkdf(STANZA_KEY_LABEL, b"", &ikm)[..TAG_BYTES]
            .try_into()
            .expect("correct tag length")
    }

    /// Exposes the wrapped public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.0
    }

    pub fn wrap_file_key(&self, file_key: &FileKey) -> RecipientLine {
        let mut csprng = rand::rng();
        let (ek, ct) = hpke_seal(
            &self.0,
            STANZA_KEY_LABEL,
            file_key.expose_secret(),
            &mut csprng,
        );
        let tag = self.tag(&ek);

        let epk_bytes = EphemeralKeyBytes::from_public_key(
            crate::recipient::PublicKey::MlKemX25519(EncappedKey::from(ek)),
        );

        RecipientLine {
            tag: tag,
            epk_bytes,
            encrypted_file_key: ct.try_into().expect("key length"),
        }
    }
}
