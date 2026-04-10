use std::time::SystemTime;

use dialoguer::Password;
use spki::{der::referenced::OwnedToRef, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::{
    builder::{profile::BuilderProfile, Builder, CertificateBuilder},
    certificate::Rfc5280,
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};
use yubikey::{
    certificate::{yubikey_signer, CertInfo, Certificate},
    piv::{generate as yubikey_generate, AlgorithmId, RetiredSlotId, SlotId},
    Key, PinPolicy, TouchPolicy, YubiKey,
};

use crate::{
    error::Error,
    fl,
    key::{self, Stub},
    native::{self},
    recipient::Recipient,
    util::{Metadata, MlKem768Extension, UsagePolicies},
    BINARY_NAME, USABLE_SLOTS,
};

pub const DEFAULT_TAG: Tag = Tag::PivP256;
pub const DEFAULT_ALGORITHM: AlgorithmId = AlgorithmId::EccP256;
pub const DEFAULT_PIN_POLICY: PinPolicy = PinPolicy::Once;
pub const DEFAULT_TOUCH_POLICY: TouchPolicy = TouchPolicy::Always;

pub struct SelfSigned {
    subject: Name,
}

impl BuilderProfile for SelfSigned {
    fn get_issuer(&self, subject: &Name) -> Name {
        // RFC 5280 Section 3.2:
        //
        // > Self-issued certificates are CA certificates in which the issuer and subject
        // > are the same entity. [..] Self-signed certificates are self-issued
        // > certificates where the digital signature may be verified by the public key
        // > bound into the certificate.
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<x509_cert::ext::Extension>> {
        Ok(vec![])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    PivX25519,
    PivP256,
    X25519,
    P256,
    KemX25519,
}

impl Tag {
    pub fn as_str(&self) -> &str {
        match self {
            Tag::PivX25519 => "piv-x25519",
            Tag::PivP256 => "piv-p256",
            Tag::X25519 => "x25519tag",
            Tag::P256 => "p256tag",
            Tag::KemX25519 => "mlkem768x25519tag",
        }
    }

    pub fn to_string(&self) -> std::string::String {
        match self {
            Tag::PivX25519 => format!("piv-p256"),
            Tag::PivP256 => format!("piv-p256"),
            Tag::X25519 => format!("x25519tag"),
            Tag::P256 => format!("p256tag"),
            Tag::KemX25519 => format!("mlkem768x25519tag"),
        }
    }
}

pub struct IdentityBuilder {
    tag: Option<Tag>,
    algorithm: Option<AlgorithmId>,
    slot: Option<RetiredSlotId>,
    force: bool,
    name: Option<String>,
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
}

impl IdentityBuilder {
    pub fn new(
        tag: Option<Tag>,
        algorithm: Option<AlgorithmId>,
        slot: Option<RetiredSlotId>,
    ) -> Self {
        IdentityBuilder {
            tag,
            algorithm,
            slot,
            name: None,
            pin_policy: None,
            touch_policy: None,
            force: false,
        }
    }

    pub fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    pub fn with_pin_policy(mut self, pin_policy: Option<PinPolicy>) -> Self {
        self.pin_policy = pin_policy;
        self
    }

    pub fn with_touch_policy(mut self, touch_policy: Option<TouchPolicy>) -> Self {
        self.touch_policy = touch_policy;
        self
    }

    pub fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub fn build(self, yubikey: &mut YubiKey) -> Result<(Stub, Recipient, Metadata), Error> {
        let tag = self.tag.unwrap_or(DEFAULT_TAG);
        let algorithm = self.algorithm.unwrap_or(DEFAULT_ALGORITHM);
        let slot = match self.slot {
            Some(slot) => {
                if !self.force {
                    // Check that the slot is empty.
                    if Key::list(yubikey)?
                        .into_iter()
                        .any(|key| key.slot() == SlotId::Retired(slot))
                    {
                        return Err(Error::SlotIsNotEmpty(slot));
                    }
                }

                // Now either the slot is empty, or --force is specified.
                slot
            }
            None => {
                // Use the first empty slot.
                let keys = Key::list(yubikey)?;
                USABLE_SLOTS
                    .iter()
                    .find(|&&slot| !keys.iter().any(|key| key.slot() == SlotId::Retired(slot)))
                    .cloned()
                    .ok_or_else(|| Error::NoEmptySlots(yubikey.serial()))?
            }
        };

        let policies = UsagePolicies {
            pin: self.pin_policy.unwrap_or(DEFAULT_PIN_POLICY),
            touch: self.touch_policy.unwrap_or(DEFAULT_TOUCH_POLICY),
        };

        eprintln!("{}", fl!("builder-gen-key"));

        // No need to ask for users to enter their PIN if the PIN policy requires it,
        // because here we _always_ require them to enter their PIN in order to access the
        // protected management key (which is necessary in order to generate identities).
        key::manage(yubikey)?;

        // Generate a new key in the selected slot.
        let generated = yubikey_generate(
            yubikey,
            SlotId::Retired(slot),
            algorithm,
            policies.pin,
            policies.touch,
        )?;
        let generated_ref: SubjectPublicKeyInfoRef =
            SubjectPublicKeyInfoOwned::owned_to_ref(&generated);

        // TODO: https://github.com/RustCrypto/formats/issues/1488
        // Document `OwnedToRef` usage in top-level docs somewhere (either of the
        // crate, or of `SubjectPublicKeyInfoOwned` so we know how to get a reference).
        let recipient =
            Recipient::from_spki(generated_ref).expect("YubiKey generates a valid pubkey");
        let stub = Stub::new(yubikey.serial(), slot, &recipient);

        eprintln!();
        eprintln!("{}", fl!("builder-gen-cert"));

        // Pick a random serial for the new self-signed certificate.
        let serial = {
            // TODO: https://github.com/RustCrypto/formats/pull/1270
            // adds `SerialNumber::generate`; use it when available.
            let mut serial = [0; 19];
            rand::fill(&mut serial);
            SerialNumber::new(&serial).expect("valid")
        };

        let name = self
            .name
            .unwrap_or(format!("age identity {}", hex::encode(stub.tag)));

        if let PinPolicy::Always = policies.pin {
            // We need to enter the PIN again.
            let pin = Password::new()
                .with_prompt(fl!(
                    "plugin-enter-pin",
                    yubikey_serial = yubikey.serial().to_string(),
                ))
                .report(true)
                .interact()?;
            yubikey.verify_pin(pin.as_bytes())?;
        }
        if let TouchPolicy::Never = policies.touch {
            // No need to touch YubiKey
        } else {
            eprintln!("{}", fl!("builder-touch-yk"));
        }

        // TODO: https://github.com/iqlusioninc/yubikey.rs/issues/581
        match (tag, algorithm) {
            (Tag::KemX25519, AlgorithmId::X25519) => {
                let kem_key = native::Kem::new();
                let kem_policy = MlKem768Extension::from(kem_key.dk.seed());
                let keys = Key::list(yubikey)?;
                let attest_key = keys
                    .iter()
                    .find(|p| p.slot() == SlotId::Signature)
                    .expect("signature key exists");
                let mut builder = CertificateBuilder::new(
                    SelfSigned {
                        subject: format!(
                            "O={BINARY_NAME},OU={},CN={name}",
                            env!("CARGO_PKG_VERSION")
                        )
                        .parse()
                        .map_err(Error::Build)?,
                    },
                    serial.clone(),
                    Validity::<Rfc5280>::new(
                        SystemTime::now().try_into().map_err(Error::Build)?,
                        x509_cert::time::Time::INFINITY,
                    ),
                    generated.clone(),
                )
                .unwrap();
                builder
                    .add_extension(&policies)
                    .map_err(|e| match e {
                        e => panic!("Cannot handle this error with the yubikey 0.8 crate: {e}"),
                    })
                    .unwrap();
                builder
                    .add_extension(&kem_policy)
                    .map_err(|e| match e {
                        e => panic!("Cannot add ML-KEM seed to certificate"),
                    })
                    .unwrap();
                let signer = yubikey_signer::Signer::<
                    '_,
                    yubikey_signer::YubiRsa<yubikey_signer::Rsa2048>,
                >::new(
                    yubikey,
                    attest_key.slot(),
                    attest_key.certificate().subject_pki(),
                )?;
                let cert = builder.build(&signer).expect("signature");
                let cert = Certificate { cert };
                cert.write(yubikey, SlotId::Retired(slot), CertInfo::Uncompressed)
                    .unwrap();
                let recipient = Recipient::from_certificate(&cert).unwrap();

                let metadata = Metadata::extract(yubikey, slot, &cert, false).unwrap();

                Ok((
                    Stub::new(yubikey.serial(), slot, &recipient),
                    recipient,
                    metadata,
                ))
            }
            (Tag::PivX25519, AlgorithmId::X25519) => {
                let buf = yubikey::piv::attest(yubikey, SlotId::Retired(slot))?;
                let cert = Certificate::from_bytes(buf)?;
                let _ = cert.write(yubikey, SlotId::Retired(slot), CertInfo::Uncompressed);

                let metadata = Metadata::extract(yubikey, slot, &cert, true).unwrap();

                Ok((
                    Stub::new(yubikey.serial(), slot, &recipient),
                    recipient,
                    metadata,
                ))
            }
            (Tag::PivP256, AlgorithmId::EccP256) => {
                let cert = Certificate::generate_self_signed::<_, p256::NistP256>(
                    yubikey,
                    SlotId::Retired(slot),
                    serial,
                    Validity::<Rfc5280>::new(
                        SystemTime::now().try_into().map_err(Error::Build)?,
                        x509_cert::time::Time::INFINITY,
                    ),
                    // TODO: https://github.com/RustCrypto/formats/issues/1489
                    format!("O={BINARY_NAME},OU={},CN={name}", env!("CARGO_PKG_VERSION"))
                        .parse()
                        .map_err(Error::Build)?,
                    generated,
                    // TODO: https://github.com/RustCrypto/formats/issues/1490
                    // TODO: https://github.com/iqlusioninc/yubikey.rs/issues/580
                    |builder| {
                        builder.add_extension(&policies).map_err(|e| match e {
                            e => panic!("Cannot handle this error with the yubikey 0.8 crate: {e}"),
                        })
                    },
                )?;

                let metadata = Metadata::extract(yubikey, slot, &cert, false).unwrap();

                Ok((
                    Stub::new(yubikey.serial(), slot, &recipient),
                    recipient,
                    metadata,
                ))
            }
            (tag, _) => Err(Error::InvalidFlagTui(tag.as_str().to_string())),
        }
    }
}
