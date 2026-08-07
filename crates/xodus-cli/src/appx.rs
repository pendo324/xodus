//! `AppxManifest.xml`/`MicrosoftGame.config` lookup/parsing for the package `xodus-cli run` just
//! extracted - `PackageFamilyName` computation so it can tell `xgameruntime.dll`/`xodus-service`
//! which catalog product the running game actually is (see [`xodus::ipc::ENV_PACKAGE_FAMILY_NAME`]),
//! and `PersistentLocalStorage`/`RelatedProducts` facts for `XPersistentLocalStorage`.
//!
//! The hash algorithm (SHA-256 of the UTF-16LE-encoded `Identity` publisher, first 8 bytes,
//! Crockford Base32) is Microsoft's own `PackageNameAndPublisherIdFromFamilyName`, reconstructed
//! from public documentation/community write-ups (not guessed) - see the `crockford_encode_lower`
//! test vectors below, taken from a reference implementation.

use std::collections::HashMap;

use msixvc::xvd::SegmentFile;
use quick_xml::events::Event;
use sha2::{Digest, Sha256};

/// Finds the package-relative path of `AppxManifest.xml` among a package's files, if present.
/// Matched by suffix (case-insensitive) rather than an exact top-level key, since real
/// packages have been observed to vary in leading path separators/casing.
pub fn find_manifest_path(lfiles: &HashMap<String, SegmentFile>) -> Option<&str> {
    lfiles
        .keys()
        .find(|path| path.to_ascii_lowercase().ends_with("appxmanifest.xml"))
        .map(String::as_str)
}

/// The two `Identity` attributes a `PackageFamilyName` is derived from.
pub struct Identity {
    pub name: String,
    pub publisher: String,
}

/// Finds the package-relative path of `MicrosoftGame.config` among a package's files, if
/// present. Same suffix-match rationale as [`find_manifest_path`].
pub fn find_game_config_path(lfiles: &HashMap<String, SegmentFile>) -> Option<&str> {
    lfiles
        .keys()
        .find(|path| path.to_ascii_lowercase().ends_with("microsoftgame.config"))
        .map(String::as_str)
}

/// A title's `<PersistentLocalStorage>` declaration from `MicrosoftGame.config`, per that file's
/// own XSD schema (`CT_PersistentLocalStorage`) rather than a guess at the shape. Backs
/// `XPersistentLocalStorageGetSpaceInfo`'s real numbers instead of a placeholder.
pub struct PersistentLocalStorageConfig {
    pub size_mb: u64,
    pub growable_to_mb: u64,
    pub shareable: bool,
}

/// A title's `<RelatedProducts>` declaration - the `StoreId`s of other products it's willing to
/// share `PersistentLocalStorage` with via `XPersistentLocalStorageMountForPackage`.
pub struct GameConfig {
    pub persistent_local_storage: Option<PersistentLocalStorageConfig>,
    pub related_products: Vec<String>,
}

/// Parses `<PersistentLocalStorage>` and `<RelatedProducts>` out of a `MicrosoftGame.config`
/// document. Deliberately doesn't model the rest of the config schema - nothing else in this
/// pipeline needs it.
pub fn parse_game_config(xml: &str) -> GameConfig {
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut persistent_local_storage = None;
    let mut related_products = Vec::new();
    let mut path: Vec<Vec<u8>> = Vec::new();
    let mut text = String::new();
    let mut current_pls = PersistentLocalStorageConfig {
        size_mb: 0,
        growable_to_mb: 0,
        shareable: false,
    };
    let mut in_pls = false;

    loop {
        match reader.read_event().ok() {
            Some(Event::Eof) | None => break,
            Some(Event::Start(tag)) => {
                let name = tag.local_name().as_ref().to_vec();
                if name == b"PersistentLocalStorage" {
                    in_pls = true;
                }
                path.push(name);
                text.clear();
            }
            Some(Event::Text(t)) => {
                if let Ok(decoded) = t.decode() {
                    text.push_str(&decoded);
                }
            }
            Some(Event::End(_)) => {
                if let Some(name) = path.pop() {
                    match name.as_slice() {
                        b"PersistentLocalStorage" => {
                            in_pls = false;
                            persistent_local_storage = Some(std::mem::replace(
                                &mut current_pls,
                                PersistentLocalStorageConfig {
                                    size_mb: 0,
                                    growable_to_mb: 0,
                                    shareable: false,
                                },
                            ));
                        }
                        b"SizeMB" if in_pls => {
                            current_pls.size_mb = text.trim().parse().unwrap_or(0)
                        }
                        b"GrowableToMB" if in_pls => {
                            current_pls.growable_to_mb = text.trim().parse().unwrap_or(0)
                        }
                        b"Shareable" if in_pls => {
                            current_pls.shareable = text.trim().eq_ignore_ascii_case("true")
                        }
                        b"RelatedProduct" => {
                            let store_id = text.trim();
                            if !store_id.is_empty() {
                                related_products.push(store_id.to_string());
                            }
                        }
                        _ => {}
                    }
                }
                text.clear();
            }
            _ => {}
        }
    }

    GameConfig {
        persistent_local_storage,
        related_products,
    }
}

/// Parses just the root `<Identity Name="..." Publisher="..." .../>` element out of an
/// `AppxManifest.xml` document. Deliberately doesn't model the rest of the manifest schema -
/// nothing else in this pipeline needs it.
pub fn parse_identity(xml: &str) -> Option<Identity> {
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    loop {
        match reader.read_event().ok()? {
            Event::Eof => return None,
            Event::Start(tag) | Event::Empty(tag) if tag.local_name().as_ref() == b"Identity" => {
                let mut name = None;
                let mut publisher = None;
                for attr in tag.attributes().flatten() {
                    #[allow(deprecated)]
                    match attr.key.local_name().as_ref() {
                        b"Name" => name = attr.unescape_value().ok().map(|v| v.into_owned()),
                        b"Publisher" => {
                            publisher = attr.unescape_value().ok().map(|v| v.into_owned())
                        }
                        _ => {}
                    }
                }
                return Some(Identity {
                    name: name?,
                    publisher: publisher?,
                });
            }
            _ => {}
        }
    }
}

/// `<Name>_<PublisherId>` - the `PackageFamilyName` computed from a package's `Identity`.
pub fn compute_package_family_name(identity: &Identity) -> String {
    format!("{}_{}", identity.name, publisher_id(&identity.publisher))
}

/// SHA-256 of the UTF-16LE-encoded publisher, first 8 bytes, Crockford Base32-encoded to a
/// 13-character lowercase "Publisher Id".
fn publisher_id(publisher: &str) -> String {
    let mut hasher = Sha256::new();
    for unit in publisher.encode_utf16() {
        hasher.update(unit.to_le_bytes());
    }
    let hash = hasher.finalize();
    crockford_encode_lower(hash[..8].try_into().unwrap())
}

/// Crockford Base32-encodes an 8-byte array into the fixed 13-character "Publisher Id" form:
/// 12 full 5-bit groups from the 64 input bits, plus a 13th character carrying the remaining
/// 4 bits left-shifted by one (a trailing zero pad bit), matching
/// `PackageNameAndPublisherIdFromFamilyName`'s behavior.
fn crockford_encode_lower(input: [u8; 8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let n = u64::from_be_bytes(input);

    let mut out = [0u8; 13];
    for (index, shift) in (4..=59).rev().step_by(5).enumerate() {
        out[index] = ALPHABET[((n >> shift) & 0x1F) as usize];
    }
    out[12] = ALPHABET[((n << 1) & 0x1F) as usize];

    String::from_utf8(out.to_vec()).expect("Crockford Base32 alphabet is ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publisher_id_matches_known_vector() {
        assert_eq!(publisher_id("Publisher Software"), "zj75k085cmj1a");
    }

    #[test]
    fn publisher_id_matches_microsoft_vector() {
        assert_eq!(
            publisher_id(
                "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
            ),
            "8wekyb3d8bbwe"
        );
    }

    #[test]
    fn package_family_name_joins_name_and_publisher_id() {
        let identity = Identity {
            name: "Microsoft.PowerShell".to_string(),
            publisher:
                "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
                    .to_string(),
        };
        assert_eq!(
            compute_package_family_name(&identity),
            "Microsoft.PowerShell_8wekyb3d8bbwe"
        );
    }

    #[test]
    fn parse_identity_extracts_name_and_publisher() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Example.Game" Publisher="CN=Example" Version="1.0.0.0" ProcessorArchitecture="x64" />
</Package>"#;
        let identity = parse_identity(xml).unwrap();
        assert_eq!(identity.name, "Example.Game");
        assert_eq!(identity.publisher, "CN=Example");
    }

    #[test]
    fn parse_game_config_extracts_persistent_local_storage_and_related_products() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Game configVersion="1">
  <PersistentLocalStorage>
    <SizeMB>128</SizeMB>
    <GrowableToMB>512</GrowableToMB>
    <Shareable>true</Shareable>
  </PersistentLocalStorage>
  <RelatedProducts>
    <RelatedProduct>9NABC1234567</RelatedProduct>
    <RelatedProduct>9NDEF7654321</RelatedProduct>
  </RelatedProducts>
</Game>"#;
        let config = parse_game_config(xml);
        let pls = config.persistent_local_storage.unwrap();
        assert_eq!(pls.size_mb, 128);
        assert_eq!(pls.growable_to_mb, 512);
        assert!(pls.shareable);
        assert_eq!(
            config.related_products,
            vec!["9NABC1234567".to_string(), "9NDEF7654321".to_string()]
        );
    }

    #[test]
    fn parse_game_config_handles_absent_elements() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?><Game configVersion="1"></Game>"#;
        let config = parse_game_config(xml);
        assert!(config.persistent_local_storage.is_none());
        assert!(config.related_products.is_empty());
    }
}
