use std::usize;

use hpke::{Deserializable, Kem as KemTrait, Serializable};
use ml_kem::{kem::Decapsulate, ml_kem_768, Encapsulate, FromSeed, KeyExport, TryKeyInit};
use sha3::{
    digest::{ExtendableOutput, FixedOutput, Update, XofReader},
    Sha3_256,
};
use typenum::{UInt, UTerm, Unsigned, B0, B1, U32};
use x509_cert::spki::ObjectIdentifier;

// KEM Parameters
pub(crate) const NENC: usize = 1120;
pub(crate) const NPK: usize = 1216;
pub(crate) const NSK: usize = 32;
pub(crate) const KEM_NCT: usize = 1088;
pub(crate) const KEM_NEK: usize = 1184;
pub(crate) const KEM_NSEED: usize = 64;
pub(crate) const GROUP_NELEM: usize = 32;
pub(crate) const GROUP_NSEED: usize = 32;

pub(crate) const STANZA_TAG: &str = "mlkem768x25519tag";
pub(crate) const STANZA_KEY_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519tag";
pub(crate) const LABEL: &[u8] = b"MLKEM768-X25519";
pub(crate) const OID_X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.58");

#[derive(Clone, Debug)]
pub struct PublicKey([u8; NPK]);

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for PublicKey {}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        let pk: [u8; NPK] = encoded.try_into().map_err(|_| {
            hpke::HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
        })?;
        Ok(Self(pk))
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
pub struct PrivateKey([u8; NSK]);

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for PrivateKey {}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        let private_key: [u8; NSK] = encoded.try_into().map_err(|_| {
            hpke::HpkeError::IncorrectInputLength(Self::OutputSize::to_usize(), encoded.len())
        })?;
        Ok(Self(private_key))
    }
}

impl Serializable for PrivateKey {
    type OutputSize = U32;
    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0);
    }
}

#[derive(Clone)]
pub struct EncappedKey([u8; NENC]);

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
    fn expand_key(seed: &[u8; NSK]) -> Self {
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
pub struct Kem;

impl KemTrait for Kem {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncappedKey = EncappedKey;
    type NSecret = U32;

    const KEM_ID: u16 = 0x647a;

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
        let sk_bytes: [u8; NSK] = sk.to_bytes().try_into().unwrap();
        let expanded_key = ExpandedKey::expand_key(&sk_bytes);
        let mut kem_public_key: [u8; NPK] = [0; NPK];
        kem_public_key[..KEM_NEK].copy_from_slice(&expanded_key.ek_pq.to_bytes()[..KEM_NEK]);
        kem_public_key[KEM_NEK..].copy_from_slice(&expanded_key.ek_t.as_bytes()[..GROUP_NELEM]);

        Self::PublicKey::from_bytes(&kem_public_key[..NPK]).expect("public key from expanded key")
    }

    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let mut ikm_bytes: [u8; NSK] = [0; NSK];
        ikm_bytes.copy_from_slice(&ikm[..NSK]);
        let expanded_key = ExpandedKey::expand_key(&ikm_bytes);
        let mut kem_public_key: [u8; NPK] = [0; NPK];
        kem_public_key[..KEM_NEK].copy_from_slice(&expanded_key.ek_pq.to_bytes()[..KEM_NEK]);
        kem_public_key[KEM_NEK..].copy_from_slice(&expanded_key.ek_t.as_bytes()[..GROUP_NELEM]);

        let private_key = Self::PrivateKey::from_bytes(&kem_public_key[..NSK])
            .expect("private key from expanded key");
        let public_key = Self::PublicKey::from_bytes(&kem_public_key[..NPK])
            .expect("public key from expanded key");
        (private_key, public_key)
    }

    fn gen_keypair<R: rand::CryptoRng + rand::Rng>(
        csprng: &mut R,
    ) -> (Self::PrivateKey, Self::PublicKey) {
        let seed = x25519_dalek::StaticSecret::random_from_rng(csprng).to_bytes();
        let expanded_key = ExpandedKey::expand_key(&seed);
        let mut kem_public_key: [u8; NPK] = [0; NPK];
        kem_public_key[..KEM_NEK].copy_from_slice(&expanded_key.ek_pq.to_bytes()[..KEM_NEK]);
        kem_public_key[KEM_NEK..].copy_from_slice(&expanded_key.ek_t.as_bytes()[..GROUP_NELEM]);

        let private_key = Self::PrivateKey::from_bytes(&kem_public_key[..NSK])
            .expect("private key from expanded key");
        let public_key = Self::PublicKey::from_bytes(&kem_public_key[..NPK])
            .expect("public key from expanded key");
        (private_key, public_key)
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
        let expanded_key = ExpandedKey::expand_key(&sk_bytes);

        let ss_pq = expanded_key.dk_pq.decapsulate(&ct_pq);
        // TODO: switch to yubikey DH
        let ss_t = x25519_dalek::x25519(ct_t, expanded_key.dk_t.as_bytes().to_owned());

        let mut ss_hash = Sha3_256::default();
        ss_hash.update(&ss_pq);
        ss_hash.update(&ss_t);
        ss_hash.update(&ct_t);
        ss_hash.update(expanded_key.ek_t.as_bytes());
        ss_hash.update(LABEL);
        let ss = hpke::kem::SharedSecret(ss_hash.finalize_fixed());
        Ok(ss)
    }

    fn encap<R: rand::rand_core::CryptoRng + rand::rand_core::RngCore>(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
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
        ss_hash.update(&ss_pq);
        ss_hash.update(ss_t.as_bytes());
        ss_hash.update(ct_t.as_bytes());
        ss_hash.update(ek_t.as_bytes());
        ss_hash.update(LABEL);
        let ss = hpke::kem::SharedSecret(ss_hash.finalize_fixed());

        let mut ct: [u8; NENC] = [0; NENC];
        ct[..KEM_NCT].copy_from_slice(&ct_pq);
        ct[KEM_NCT..].copy_from_slice(&ct_t.as_bytes()[..GROUP_NELEM]);
        let ek = Self::EncappedKey::from_bytes(&ct[..NENC])?;

        Ok((ss, ek))
    }
}
