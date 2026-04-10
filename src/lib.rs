#![forbid(unsafe_code)]
use i18n_embed::fluent::{fluent_language_loader, FluentLanguageLoader};
use lazy_static::lazy_static;
use rust_embed::RustEmbed;
use yubikey::piv::RetiredSlotId;

pub mod builder;
pub mod error;
pub mod key;
pub mod native;
pub mod p256;
pub mod plugin;
pub mod util;
pub mod x25519;

pub mod recipient;

pub const PLUGIN_NAME: &str = "yubikey";
pub const BINARY_NAME: &str = "age-plugin-yubikey";
pub const IDENTITY_PREFIX: &str = "age-plugin-yubikey-";

pub const USABLE_SLOTS: [RetiredSlotId; 20] = [
    RetiredSlotId::R1,
    RetiredSlotId::R2,
    RetiredSlotId::R3,
    RetiredSlotId::R4,
    RetiredSlotId::R5,
    RetiredSlotId::R6,
    RetiredSlotId::R7,
    RetiredSlotId::R8,
    RetiredSlotId::R9,
    RetiredSlotId::R10,
    RetiredSlotId::R11,
    RetiredSlotId::R12,
    RetiredSlotId::R13,
    RetiredSlotId::R14,
    RetiredSlotId::R15,
    RetiredSlotId::R16,
    RetiredSlotId::R17,
    RetiredSlotId::R18,
    RetiredSlotId::R19,
    RetiredSlotId::R20,
];

#[derive(RustEmbed)]
#[folder = "i18n"]
pub struct Translations;

pub const TRANSLATIONS: Translations = Translations {};

lazy_static! {
    pub static ref LANGUAGE_LOADER: FluentLanguageLoader = fluent_language_loader!();
}

#[macro_export]
macro_rules! fl {
    ($message_id:literal) => {{
        i18n_embed_fl::fl!($crate::LANGUAGE_LOADER, $message_id)
    }};
    ($message_id:literal, $($kwarg:expr),* $(,)*) => {{
        i18n_embed_fl::fl!($crate::LANGUAGE_LOADER, $message_id, $($kwarg,)*)
    }};
}
