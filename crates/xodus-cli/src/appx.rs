//! `AppxManifest.xml` lookup/parsing and `PackageFamilyName` computation for the package
//! `xodus-cli run` just extracted - so it can tell `xgameruntime.dll`/`xodus-service` which
//! catalog product the running game actually is (see [`xodus::ipc::ENV_PACKAGE_FAMILY_NAME`]).
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
    format!(
        "{}_{}",
        identity.name,
        publisher_id(&identity.publisher)
    )
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
            publisher: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US".to_string(),
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
}
