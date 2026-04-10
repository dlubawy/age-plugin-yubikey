use std::fmt;
use std::iter;
use std::usize;

use base64::{
    prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD},
    Engine,
};
use const_oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::{
    der::{
        self,
        asn1::OctetString,
        oid::db::rfc4519::{COMMON_NAME, ORGANIZATION_NAME},
        Decode,
    },
    ext::{Criticality, ToExtension},
};
use yubikey::{
    piv::{AlgorithmId, RetiredSlotId, SlotId},
    Certificate, PinPolicy, Serial, TouchPolicy, YubiKey,
};

use crate::fl;
use crate::{
    builder::Tag, error::Error, key::Stub, native::NSK, recipient::Recipient, BINARY_NAME,
    USABLE_SLOTS,
};

pub const POLICY_EXTENSION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");

pub const ML_KEM_768_EXTENSION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55738.666.5");

pub fn ui_to_slot(slot: u8) -> Result<RetiredSlotId, Error> {
    // Use 1-indexing in the UI for niceness
    USABLE_SLOTS
        .get(slot as usize - 1)
        .cloned()
        .ok_or(Error::InvalidSlot(slot))
}

pub fn slot_to_ui(slot: &RetiredSlotId) -> u8 {
    // Use 1-indexing in the UI for niceness
    USABLE_SLOTS.iter().position(|s| s == slot).unwrap() as u8 + 1
}

pub struct UsagePolicies {
    pub pin: PinPolicy,
    pub touch: TouchPolicy,
}

impl AssociatedOid for UsagePolicies {
    const OID: ObjectIdentifier = POLICY_EXTENSION_OID;
}

impl der::Encode for UsagePolicies {
    fn encoded_len(&self) -> der::Result<der::Length> {
        Ok(der::Length::new(2))
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        // TODO: https://github.com/RustCrypto/formats/issues/1490
        // Is this the correct encoding?
        encoder.write(&[self.pin.into(), self.touch.into()])
    }
}

impl<'a> der::Decode<'a> for UsagePolicies {
    type Error = der::Error;

    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        // TODO: https://github.com/RustCrypto/formats/issues/1492
        let pin = decoder
            .read_byte()?
            .try_into()
            .map_err(|_| decoder.error(der::ErrorKind::Failed))?;
        let touch = decoder
            .read_byte()?
            .try_into()
            .map_err(|_| decoder.error(der::ErrorKind::Failed))?;
        Ok(Self { pin, touch })
    }
}

impl ToExtension for UsagePolicies {
    type Error = der::Error;
    fn to_extension(
        self,
        _subject: &x509_cert::name::Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> Result<x509_cert::ext::Extension, Self::Error> {
        // TODO: https://github.com/RustCrypto/formats/issues/1490
        let extn_value: &[u8; 21] = b"1.3.6.1.4.1.41482.3.8";
        Ok(x509_cert::ext::Extension {
            extn_id: POLICY_EXTENSION_OID,
            critical: false,
            extn_value: OctetString::new(*extn_value)?,
        })
    }
}

impl Criticality for UsagePolicies {
    fn criticality(
        &self,
        _subject: &x509_cert::name::Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> bool {
        false
    }
}

pub struct MlKem768Extension([u8; NSK]);

impl MlKem768Extension {
    pub fn as_bytes(&self) -> &[u8; NSK] {
        &self.0
    }
}

impl From<[u8; NSK]> for MlKem768Extension {
    fn from(value: [u8; NSK]) -> Self {
        Self(value)
    }
}

impl AssociatedOid for MlKem768Extension {
    const OID: ObjectIdentifier = ML_KEM_768_EXTENSION_OID;
}

impl der::Encode for MlKem768Extension {
    fn encoded_len(&self) -> der::Result<der::Length> {
        Ok(der::Length::new(43))
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        // TODO: https://github.com/RustCrypto/formats/issues/1490
        // Is this the correct encoding?
        let mut encoded_bytes: [u8; 43] = [0; 43];
        BASE64_STANDARD_NO_PAD
            .encode_slice(self.0, &mut encoded_bytes)
            .unwrap();
        encoder.write(&encoded_bytes)
    }
}

impl<'a> der::Decode<'a> for MlKem768Extension {
    type Error = der::Error;

    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        // TODO: https://github.com/RustCrypto/formats/issues/1492
        let mut encoded_bytes: [u8; 43] = [0; 43];
        decoder
            .read_into(&mut encoded_bytes)
            .expect("base64 length");
        let mut seed: [u8; NSK] = [0; NSK];
        BASE64_STANDARD_NO_PAD
            .decode_slice_unchecked(encoded_bytes, &mut seed)
            .unwrap();
        Ok(Self(seed))
    }
}

impl ToExtension for MlKem768Extension {
    type Error = der::Error;
    fn to_extension(
        self,
        _subject: &x509_cert::name::Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> Result<x509_cert::ext::Extension, Self::Error> {
        // TODO: https://github.com/RustCrypto/formats/issues/1490
        let extn_value: &[u8; 23] = b"1.3.6.1.4.1.55738.666.5";
        Ok(x509_cert::ext::Extension {
            extn_id: ML_KEM_768_EXTENSION_OID,
            critical: false,
            extn_value: OctetString::new(*extn_value)?,
        })
    }
}

impl Criticality for MlKem768Extension {
    fn criticality(
        &self,
        _subject: &x509_cert::name::Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> bool {
        false
    }
}

pub fn tag_from_string(s: String) -> Result<Tag, Error> {
    match s.as_str() {
        "piv-p256" => Ok(Tag::PivP256),
        "piv-x25519" => Ok(Tag::PivX25519),
        _ => Err(Error::InvalidFlagTui(s)),
    }
}

pub fn algorithm_from_string(s: String) -> Result<AlgorithmId, Error> {
    match s.as_str() {
        "ECCP256" => Ok(AlgorithmId::EccP256),
        "X25519" => Ok(AlgorithmId::X25519),
        _ => Err(Error::YubiKey(yubikey::Error::AlgorithmError)),
    }
}

pub fn pin_policy_from_string(s: String) -> Result<PinPolicy, Error> {
    match s.as_str() {
        "always" => Ok(PinPolicy::Always),
        "once" => Ok(PinPolicy::Once),
        "never" => Ok(PinPolicy::Never),
        _ => Err(Error::InvalidPinPolicy(s)),
    }
}

pub fn touch_policy_from_string(s: String) -> Result<TouchPolicy, Error> {
    match s.as_str() {
        "always" => Ok(TouchPolicy::Always),
        "cached" => Ok(TouchPolicy::Cached),
        "never" => Ok(TouchPolicy::Never),
        _ => Err(Error::InvalidTouchPolicy(s)),
    }
}

pub fn pin_policy_to_str(policy: Option<PinPolicy>) -> String {
    match policy {
        Some(PinPolicy::Always) => fl!("pin-policy-always"),
        Some(PinPolicy::Once) => fl!("pin-policy-once"),
        Some(PinPolicy::Never) => fl!("pin-policy-never"),
        _ => fl!("unknown-policy"),
    }
}

pub fn touch_policy_to_str(policy: Option<TouchPolicy>) -> String {
    match policy {
        Some(TouchPolicy::Always) => fl!("touch-policy-always"),
        Some(TouchPolicy::Cached) => fl!("touch-policy-cached"),
        Some(TouchPolicy::Never) => fl!("touch-policy-never"),
        _ => fl!("unknown-policy"),
    }
}

const MODHEX: &str = "cbdefghijklnrtuv";
pub fn otp_serial_prefix(serial: Serial) -> String {
    iter::repeat(0)
        .take(4)
        .chain((0..8).rev().map(|i| (serial.0 >> (4 * i)) & 0x0f))
        .map(|i| MODHEX.char_indices().nth(i as usize).unwrap().1)
        .collect()
}

pub fn extract_name(cert: &x509_cert::Certificate, all: bool) -> Option<(String, bool)> {
    // Look at Subject Organization to determine if we created this.
    match cert
        .tbs_certificate()
        .subject()
        // TODO: https://github.com/RustCrypto/formats/issues/1493
        // Replicate `iter_organization` from `x509-parser`, or figure out some
        // other way to reliably access common / predictable parts of a subject. Could
        // maybe gate a getter on a concrete `Profile` (or on a sub-trait)?
        .as_ref()
        .iter()
        .flat_map(|n| n.as_ref().iter().find(|a| a.oid == ORGANIZATION_NAME))
        .next()
    {
        Some(org) if org.value.decode_as::<String>().as_deref() == Ok(BINARY_NAME) => {
            // We store the identity name as a Common Name attribute.
            let name = cert
                .tbs_certificate()
                .subject()
                // TODO: https://github.com/RustCrypto/formats/issues/1493
                .as_ref()
                .iter()
                .flat_map(|n| n.as_ref().iter().find(|a| a.oid == COMMON_NAME))
                .next()
                .and_then(|cn| cn.value.decode_as::<String>().ok())
                .unwrap_or_default(); // TODO: This should always be present.

            Some((name, true))
        }
        _ => {
            // Not one of ours, but we've already filtered for compatibility.
            if !all {
                return None;
            }

            // Display the entire subject.
            let name = cert.tbs_certificate().subject().to_string();

            Some((name, false))
        }
    }
}

pub struct Metadata {
    serial: Serial,
    slot: RetiredSlotId,
    name: String,
    created: String,
    pub pin_policy: Option<PinPolicy>,
    pub touch_policy: Option<TouchPolicy>,
}

impl Metadata {
    pub fn extract(
        yubikey: &mut YubiKey,
        slot: RetiredSlotId,
        cert: &Certificate,
        all: bool,
    ) -> Option<Self> {
        // We store the PIN and touch policies for identities in their certificates
        // using the same certificate extension as PIV attestations.
        // https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
        let policies = |c: &x509_cert::Certificate| {
            c.tbs_certificate()
                // TODO: https://github.com/RustCrypto/formats/issues/1491
                .get_extension::<UsagePolicies>()
                .ok()
                .flatten()
                .map(|(_critical, policies)| {
                    // We should only ever see one of the three concrete values for either
                    // policy, but handle unknown values just in case.
                    (
                        match policies.pin {
                            PinPolicy::Default => None,
                            p => Some(p),
                        },
                        match policies.touch {
                            TouchPolicy::Default => None,
                            p => Some(p),
                        },
                    )
                })
                .unwrap_or((None, None))
        };

        extract_name(&cert.cert, all)
            .map(|(name, ours)| {
                if ours {
                    let (pin_policy, touch_policy) = policies(&cert.cert);
                    (name, pin_policy, touch_policy)
                } else {
                    // We can extract the PIN and touch policies via an attestation. This
                    // is slow, but the user has asked for all compatible keys, so...
                    let (pin_policy, touch_policy) =
                        yubikey::piv::attest(yubikey, SlotId::Retired(slot))
                            .ok()
                            .and_then(|buf| {
                                x509_cert::Certificate::from_der(&buf)
                                    .map(|c| policies(&c))
                                    .ok()
                            })
                            .unwrap_or((None, None));

                    (name, pin_policy, touch_policy)
                }
            })
            .map(|(name, pin_policy, touch_policy)| Metadata {
                serial: yubikey.serial(),
                slot,
                name,
                created: chrono::DateTime::<chrono::Utc>::from(
                    cert.cert
                        .tbs_certificate()
                        .validity()
                        .not_before
                        .to_system_time(),
                )
                .to_rfc2822(),
                pin_policy,
                touch_policy,
            })
    }
}

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            fl!(
                "yubikey-metadata",
                serial = self.serial.to_string(),
                slot = slot_to_ui(&self.slot),
                name = self.name.as_str(),
                created = self.created.as_str(),
                pin_policy = pin_policy_to_str(self.pin_policy),
                touch_policy = touch_policy_to_str(self.touch_policy),
            )
        )
    }
}

pub fn print_identity(stub: Stub, recipient: Recipient, metadata: Metadata) {
    let recipient = recipient.to_string();
    if !console::user_attended() {
        let recipient = recipient.as_str();
        eprintln!("{}", fl!("print-recipient", recipient = recipient));
    }

    println!(
        "{}",
        fl!(
            "yubikey-identity",
            yubikey_metadata = metadata.to_string(),
            recipient = recipient,
            identity = stub.to_string(),
        )
    );
}

pub fn base64_arg<A: AsRef<[u8]>, B: AsMut<[u8]>>(arg: &A, mut buf: B) -> Option<B> {
    if arg.as_ref().len() != ((4 * buf.as_mut().len()) + 2) / 3 {
        return None;
    }

    BASE64_STANDARD_NO_PAD
        .decode_slice_unchecked(arg, buf.as_mut())
        .ok()
        .and_then(|len| (len == buf.as_mut().len()).then_some(buf))
}
