use hpke::{Deserializable, Kem as KemTrait, Serializable};
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use typenum::{UInt, UTerm, Unsigned, B0, B1, U32};
use x509_cert::spki::ObjectIdentifier;

pub(crate) const NPK: usize = 1216;
pub(crate) const NSK: usize = 32;
pub(crate) const NENC: usize = 1120;
pub(crate) const STANZA_TAG: &str = "mlkem768x25519tag";
pub(crate) const STANZA_KEY_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519tag";
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

// fn expand_key(seed: &[u8; NSK]) -> PublicKey {
//     let seed_pq = [0; 64];
//     let seed_t = [0; 32];
//     let xof = sha3::Shake256::default().chain(seed).finalize_xof();
//     xof.read(&mut seed_pq);
//     xof.read(&mut seed_t);
// }

#[derive(Clone)]
pub struct Kem;

impl KemTrait for Kem {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncappedKey = EncappedKey;
    type NSecret = U32;

    const KEM_ID: u16 = 0x647a;

    fn sk_to_pk(_sk: &Self::PrivateKey) -> Self::PublicKey {
        PublicKey(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned())
    }

    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        todo!()
    }

    fn gen_keypair<R: rand_core::CryptoRng + rand_core::RngCore>(
        csprng: &mut R,
    ) -> (Self::PrivateKey, Self::PublicKey) {
        todo!()
    }

    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<hpke::kem::SharedSecret<Self>, hpke::HpkeError> {
        todo!()
    }

    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(hpke::kem::SharedSecret<Self>, Self::EncappedKey), hpke::HpkeError> {
        todo!()
    }
}
