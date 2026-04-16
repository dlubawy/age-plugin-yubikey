use age_core::{format::FileKey, primitives::bech32_encode_to_fmt, secrecy::ExposeSecret};
use hpke::{Deserializable, Kem as KemTrait, Serializable};
use ml_kem::{kem::Decapsulate, ml_kem_768, Encapsulate, FromSeed, KeyExport, TryKeyInit};
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
pub const LABEL: &[u8] = b"\\.//^\\";
pub const RECIPIENT_PREFIX: bech32::Hrp = bech32::Hrp::parse_unchecked("age1tagpq");

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
pub struct PublicKey {
    ek: [u8; NPK],
    pub ek_pq: ml_kem_768::EncapsulationKey,
    pub ek_t: x25519_dalek::PublicKey,
}

impl PublicKey {
    pub fn from(ek_pq: ml_kem_768::EncapsulationKey, ek_t: x25519_dalek::PublicKey) -> Self {
        let mut ek_bytes: [u8; NPK] = [0; NPK];
        ek_bytes[..KEM_NEK].copy_from_slice(ek_pq.to_bytes().as_slice());
        ek_bytes[KEM_NEK..].copy_from_slice(ek_t.to_bytes().as_slice());
        Self {
            ek: ek_bytes,
            ek_pq,
            ek_t,
        }
    }

    pub fn as_bytes(&self) -> &[u8; NPK] {
        &self.ek
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.ek == other.ek
    }
}

impl Eq for PublicKey {}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        if encoded.len() != NPK {
            return Err(hpke::HpkeError::IncorrectInputLength(
                Self::OutputSize::to_usize(),
                encoded.len(),
            ));
        };
        let ek_pq = ml_kem_768::EncapsulationKey::new_from_slice(&encoded[..KEM_NEK])
            .expect("ek_pq length");
        let mut ek_t_bytes: [u8; GROUP_NELEM] = [0; GROUP_NELEM];
        ek_t_bytes.copy_from_slice(&encoded[KEM_NEK..]);
        let ek_t = x25519_dalek::PublicKey::try_from(ek_t_bytes).expect("ek_t length");
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
        buf.copy_from_slice(&self.ek);
    }
}

pub struct ExpandedKey {
    pub(crate) ek_pq: ml_kem_768::EncapsulationKey,
    pub(crate) ek_t: x25519_dalek::PublicKey,
    pub(crate) dk_pq: ml_kem_768::DecapsulationKey,
    pub(crate) dk_t: x25519_dalek::StaticSecret,
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

        let dk_t = x25519_dalek::StaticSecret::try_from(seed_bytes_t).expect("ek_t static secret");
        let ek_t = x25519_dalek::PublicKey::from(&dk_t);

        ExpandedKey {
            ek_pq,
            ek_t,
            dk_pq,
            dk_t,
        }
    }
}

#[derive(Clone)]
pub struct PrivateKey([u8; NSK]);

impl PrivateKey {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn expand_key(&self) -> ExpandedKey {
        ExpandedKey::from(&self.0)
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
        let seed: [u8; NSK] = encoded.try_into().map_err(|_| {
            hpke::HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
        })?;
        Ok(Self(seed))
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
            .expect("Kem seed")
        {
            (false, ext) => {
                let seed: &[u8; NSK] = ext.as_bytes();
                let expanded_key: ExpandedKey = ExpandedKey::from(seed);
                let ek_t_data: [u8; GROUP_NELEM] = cert
                    .subject_pki()
                    .subject_public_key
                    .raw_bytes()
                    .try_into()
                    .expect("invalid spki");
                let ek_t = x25519_dalek::PublicKey::from(ek_t_data);
                let ek = PublicKey::from(expanded_key.ek_pq, ek_t);
                let dk = PrivateKey::from_bytes(seed).unwrap();
                Ok(Self { ek, dk })
            }
            _ => Err(hpke::HpkeError::InvalidPskBundle),
        }
    }

    pub fn from(seed: &[u8; NSK], ek_t_bytes: &[u8; GROUP_NELEM]) -> Self {
        let dk = PrivateKey::from_bytes(seed).expect("seed length");
        let expanded_key: ExpandedKey = dk.expand_key();
        let ek_t = x25519_dalek::PublicKey::from(ek_t_bytes.to_owned());
        let ek = PublicKey::from(expanded_key.ek_pq, ek_t);
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
        let expanded_key: ExpandedKey = sk.expand_key();
        PublicKey::from(expanded_key.ek_pq, expanded_key.ek_t)
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

        let dk = PrivateKey::from_bytes(&seed).expect("private key");
        let ek = Kem::sk_to_pk(&dk);
        (dk, ek)
    }

    fn gen_keypair<R: rand::CryptoRng + rand::Rng>(
        csprng: &mut R,
    ) -> (Self::PrivateKey, Self::PublicKey) {
        let mut seed: [u8; NSK] = [0; NSK];
        csprng
            .try_fill_bytes(&mut seed)
            .expect("seed of proper length");
        let dk = PrivateKey::from_bytes(&seed).expect("private key");
        let ek = Kem::sk_to_pk(&dk);
        (dk, ek)
    }

    // NOTE: for implementation only
    // decap should happen from key
    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<hpke::kem::SharedSecret<Self>, hpke::HpkeError> {
        let encapped_key_bytes = encapped_key.to_bytes();
        let ct_pq_bytes: [u8; KEM_NCT] =
            encapped_key_bytes[..KEM_NCT].try_into().expect("ct length");
        let ct_pq: ml_kem::Ciphertext<ml_kem::MlKem768> = ct_pq_bytes.into();
        let ct_t_bytes: [u8; GROUP_NELEM] =
            encapped_key_bytes[KEM_NCT..].try_into().expect("ct length");
        let ct_t = x25519_dalek::PublicKey::from(ct_t_bytes);

        let expanded_key: ExpandedKey = sk_recip.expand_key();

        let ss_pq = expanded_key.dk_pq.decapsulate(&ct_pq);
        let ss_t = expanded_key.dk_t.diffie_hellman(&ct_t);

        let mut ss_hash = Sha3_256::default();
        Sha3Digest::update(&mut ss_hash, &ss_pq);
        Sha3Digest::update(&mut ss_hash, &ss_t);
        Sha3Digest::update(&mut ss_hash, &ct_t);
        Sha3Digest::update(&mut ss_hash, pk_sender_id.unwrap().ek_t.as_bytes());
        Sha3Digest::update(&mut ss_hash, LABEL);
        let ss = hpke::kem::SharedSecret(ss_hash.finalize_fixed());
        Ok(ss)
    }

    fn encap<R: rand::rand_core::CryptoRng + rand::rand_core::Rng>(
        pk_recip: &Self::PublicKey,
        _sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(hpke::kem::SharedSecret<Self>, Self::EncappedKey), hpke::HpkeError> {
        let (ct_pq, ss_pq) = pk_recip.ek_pq.encapsulate_with_rng(csprng);

        let sk_e = x25519_dalek::EphemeralSecret::random_from_rng(csprng);
        let ct_t = x25519_dalek::PublicKey::from(&sk_e);
        let ss_t = sk_e.diffie_hellman(&pk_recip.ek_t);

        let mut ss_hash = Sha3_256::default();
        Sha3Digest::update(&mut ss_hash, &ss_pq);
        Sha3Digest::update(&mut ss_hash, ss_t.as_bytes());
        Sha3Digest::update(&mut ss_hash, ct_t.as_bytes());
        Sha3Digest::update(&mut ss_hash, pk_recip.ek_t.as_bytes());
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
        bech32_encode_to_fmt(f, RECIPIENT_PREFIX, self.0.as_bytes())
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
        match Kem::try_from_certificate(cert) {
            Ok(kem) => Some(Self(kem.ek)),
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

    pub fn tag(&self) -> [u8; TAG_BYTES] {
        Sha256::digest(self.0.ek_t.as_bytes())[0..TAG_BYTES]
            .try_into()
            .expect("correct tag length")
        // let mut ikm: [u8; NENC + TAG_BYTES] = [0; NENC + TAG_BYTES];
        // ikm[..NENC].copy_from_slice(&enc.as_bytes()[..NENC]);
        // ikm[NENC..].copy_from_slice(&encoded_pk[..TAG_BYTES]);
        // hkdf(STANZA_KEY_LABEL, b"", &ikm)[..TAG_BYTES]
        //     .try_into()
        //     .expect("correct tag length")
    }

    /// Exposes the wrapped public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.0
    }

    pub fn wrap_file_key(&self, file_key: &FileKey) -> RecipientLine {
        let mut csprng = rand::rng();
        let (enc, ct) = hpke_seal(
            &self.0,
            STANZA_KEY_LABEL,
            file_key.expose_secret(),
            &mut csprng,
        );
        let tag = self.tag();

        let epk_bytes =
            EphemeralKeyBytes::from_public_key(crate::recipient::PublicKey::MlKemX25519(enc));

        RecipientLine {
            tag: tag,
            epk_bytes,
            encrypted_file_key: ct.try_into().expect("key length"),
        }
    }
}
