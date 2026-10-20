// SPDX-FileCopyrightText: 2025 Obsidian Systems
// SPDX-License-Identifier: MIT

//! Pure `ValidPathInfo`, `NarHash`, and related types for Nix store metadata.
//!
//! Quarantined from `harmonia-store-derivation` because `ValidPathInfo` is a
//! bag of loosely related fields that doesn't benefit from being in core.
//! Protocol-specific wire format derives are added in the protocol layer.

mod nar_hash;

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::io::Write as _;
use std::num::NonZero;

#[cfg(any(test, feature = "test"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize, Serializer};

pub use nar_hash::NarHash;

use harmonia_store_content_address::ContentAddress;
use harmonia_store_path::{StoreDir, StorePath, StorePathHash};
use harmonia_utils_base_encoding::base32;
use harmonia_utils_signature::Signature;
#[cfg(any(test, feature = "test"))]
use harmonia_utils_signature::proptests::arb_signatures;

/// Generate a fingerprint for signing a store path.
///
/// The fingerprint format is:
/// `1;<store-path>;<nar-hash>;<nar-size>;<comma-separated-references>`
///
/// # Arguments
/// * `store_dir` - The Nix store directory
/// * `store_path` - The store path to fingerprint
/// * `nar_hash` - The NAR hash (always SHA256)
/// * `nar_size` - The size of the NAR in bytes
/// * `references` - Sorted references to other store paths
pub fn fingerprint_path(
    store_dir: &StoreDir,
    store_path: &StorePath,
    nar_hash: &NarHash,
    nar_size: u64,
    references: &BTreeSet<StorePath>,
) -> Vec<u8> {
    const NAR_HASH_PREFIX: &[u8] = b"sha256:";
    let store_dir = store_dir.to_str().as_bytes();
    // Length of `<store-dir>/<hash>-<name>`.
    let path_len = |path: &StorePath| {
        store_dir.len() + 1 + StorePathHash::encoded_len() + 1 + path.name().len()
    };
    let nar_hash_len = base32::encode_len(nar_hash.digest_bytes().len());
    let nar_size_len = nar_size.checked_ilog10().unwrap_or(0) as usize + 1;
    let len = 2 // "1;"
        + path_len(store_path) + 1
        + NAR_HASH_PREFIX.len() + nar_hash_len + 1
        + nar_size_len + 1
        + references.iter().map(path_len).sum::<usize>()
        + references.len().saturating_sub(1); // commas between references

    // Pushing the paths and hashes takes half the instructions of `write!`ing
    // them through `Display`, even into this same buffer.
    let mut out = Vec::with_capacity(len);
    let push_base32 = |out: &mut Vec<u8>, bytes: &[u8]| {
        let start = out.len();
        out.resize(start + base32::encode_len(bytes.len()), 0);
        base32::encode_mut(bytes, &mut out[start..]);
    };
    let push_path = |out: &mut Vec<u8>, path: &StorePath| {
        out.extend_from_slice(store_dir);
        out.push(b'/');
        push_base32(out, path.hash().as_ref());
        out.push(b'-');
        out.extend_from_slice(path.name().as_bytes());
    };

    out.extend_from_slice(b"1;");
    push_path(&mut out, store_path);
    out.push(b';');
    out.extend_from_slice(NAR_HASH_PREFIX);
    push_base32(&mut out, nar_hash.digest_bytes());
    write!(out, ";{nar_size};").expect("writing to a Vec cannot fail");
    for (i, reference) in references.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        push_path(&mut out, reference);
    }
    debug_assert_eq!(out.len(), len);
    out
}

/// Serializes in "pure" format, omitting impure fields when they have default values.
/// Used for content-addressed paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pure<T>(pub T);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(any(test, feature = "test"), derive(Arbitrary))]
pub struct UnkeyedValidPathInfo {
    pub deriver: Option<StorePath>,
    pub nar_hash: NarHash,
    pub references: BTreeSet<StorePath>,
    pub registration_time: Option<NonZero<i64>>,
    pub nar_size: u64,
    pub ultimate: bool,
    #[cfg_attr(any(test, feature = "test"), proptest(strategy = "arb_signatures()"))]
    pub signatures: BTreeSet<Signature>,
    pub ca: Option<ContentAddress>,
    pub store_dir: StoreDir,
}

impl UnkeyedValidPathInfo {
    /// Clear impure-only fields, keeping only the content-addressed metadata.
    pub fn into_pure(mut self) -> Self {
        self.deriver = None;
        self.registration_time = None;
        self.ultimate = false;
        self.signatures = BTreeSet::new();
        self
    }
}

/// Pairs a `StorePath` key with some unkeyed payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(any(test, feature = "test"), derive(Arbitrary))]
pub struct StorePathKeyed<T> {
    pub path: StorePath,
    pub info: T,
}

/// A valid store path with its metadata.
pub type ValidPathInfo = StorePathKeyed<UnkeyedValidPathInfo>;

// -- JSON serialization (version 3) ------------------------------------------

fn is_false(b: &bool) -> bool {
    !b
}

fn is_none_store_path(opt: &Option<Cow<'_, StorePath>>) -> bool {
    opt.is_none()
}

#[expect(clippy::ptr_arg, reason = "needed for serde skip_serializing_if")]
fn is_empty_signatures(set: &Cow<'_, BTreeSet<Signature>>) -> bool {
    set.is_empty()
}

/// Pure format: omits default impure fields during serialization
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawUnkeyedValidPathInfoPure<'a> {
    ca: Option<ContentAddress>,
    #[serde(skip_serializing_if = "is_none_store_path")]
    deriver: Option<Cow<'a, StorePath>>,
    nar_hash: NarHash,
    nar_size: u64,
    references: Cow<'a, BTreeSet<StorePath>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registration_time: Option<i64>,
    #[serde(skip_serializing_if = "is_empty_signatures")]
    signatures: Cow<'a, BTreeSet<Signature>>,
    store_dir: Cow<'a, StoreDir>,
    #[serde(skip_serializing_if = "is_false")]
    ultimate: bool,
    version: u32,
}

fn default_cow_set<T: Ord + Clone>() -> Cow<'static, BTreeSet<T>> {
    Cow::Owned(BTreeSet::new())
}

fn default_cow_store_dir() -> Cow<'static, StoreDir> {
    Cow::Owned(StoreDir::default())
}

/// Impure format: includes all fields, used for both serialize and deserialize
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawUnkeyedValidPathInfo<'a> {
    ca: Option<ContentAddress>,
    #[serde(default)]
    deriver: Option<Cow<'a, StorePath>>,
    nar_hash: NarHash,
    nar_size: u64,
    #[serde(default = "default_cow_set")]
    references: Cow<'a, BTreeSet<StorePath>>,
    #[serde(default)]
    registration_time: Option<i64>,
    #[serde(default = "default_cow_set")]
    signatures: Cow<'a, BTreeSet<Signature>>,
    #[serde(default = "default_cow_store_dir")]
    store_dir: Cow<'a, StoreDir>,
    #[serde(default)]
    ultimate: bool,
    version: u32,
}

fn serialize_impure<S>(info: &UnkeyedValidPathInfo, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let raw = RawUnkeyedValidPathInfo {
        ca: info.ca,
        deriver: info.deriver.as_ref().map(Cow::Borrowed),
        nar_hash: info.nar_hash,
        nar_size: info.nar_size,
        references: Cow::Borrowed(&info.references),
        registration_time: info.registration_time.map(|n| n.get()),
        signatures: Cow::Borrowed(&info.signatures),
        store_dir: Cow::Borrowed(&info.store_dir),
        ultimate: info.ultimate,
        version: 3,
    };
    raw.serialize(serializer)
}

fn deserialize_info<'de, D>(deserializer: D) -> Result<UnkeyedValidPathInfo, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = RawUnkeyedValidPathInfo::deserialize(deserializer)?;
    if raw.version != 3 {
        return Err(serde::de::Error::custom(format!(
            "unsupported path-info version: {}, expected 3",
            raw.version
        )));
    }
    Ok(UnkeyedValidPathInfo {
        deriver: raw.deriver.map(Cow::into_owned),
        nar_hash: raw.nar_hash,
        references: raw.references.into_owned(),
        registration_time: raw.registration_time.and_then(NonZero::new),
        nar_size: raw.nar_size,
        ultimate: raw.ultimate,
        signatures: raw.signatures.into_owned(),
        ca: raw.ca,
        store_dir: raw.store_dir.into_owned(),
    })
}

/// Default: impure format
impl Serialize for UnkeyedValidPathInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_impure(self, serializer)
    }
}

impl<'de> Deserialize<'de> for UnkeyedValidPathInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_info(deserializer)
    }
}

impl Serialize for Pure<UnkeyedValidPathInfo> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let raw = RawUnkeyedValidPathInfoPure {
            ca: self.0.ca,
            deriver: self.0.deriver.as_ref().map(Cow::Borrowed),
            nar_hash: self.0.nar_hash,
            nar_size: self.0.nar_size,
            references: Cow::Borrowed(&self.0.references),
            registration_time: self.0.registration_time.map(|n| n.get()),
            signatures: Cow::Borrowed(&self.0.signatures),
            store_dir: Cow::Borrowed(&self.0.store_dir),
            ultimate: self.0.ultimate,
            version: 3,
        };
        raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Pure<UnkeyedValidPathInfo> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_info(deserializer).map(Pure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harmonia_utils_hash::HashFormat as _;
    use harmonia_utils_hash::fmt::Base32;
    use proptest::collection::btree_set;
    use proptest::prelude::*;

    /// Builds the fingerprint through `Display`, the way `fingerprint_path`
    /// did before. The proptest compares the two because signatures cover
    /// these bytes.
    fn fingerprint_path_reference(
        store_dir: &StoreDir,
        store_path: &StorePath,
        nar_hash: &NarHash,
        nar_size: u64,
        references: &BTreeSet<StorePath>,
    ) -> Vec<u8> {
        let references: Vec<String> = references
            .iter()
            .map(|r| store_dir.display(r).to_string())
            .collect();
        format!(
            "1;{};{};{nar_size};{}",
            store_dir.display(store_path),
            nar_hash.as_base32(),
            references.join(",")
        )
        .into_bytes()
    }

    proptest! {
        #[test]
        fn proptest_fingerprint_path_matches_reference(
            store_dir in any::<StoreDir>(),
            store_path in any::<StorePath>(),
            nar_hash in any::<NarHash>(),
            nar_size in any::<u64>(),
            // `any::<u64>()` gives mostly 20-digit sizes. Shifting covers every
            // digit count.
            shift in 0..u64::BITS,
            references in btree_set(any::<StorePath>(), 0..30),
        ) {
            let nar_size = nar_size >> shift;
            prop_assert_eq!(
                fingerprint_path(&store_dir, &store_path, &nar_hash, nar_size, &references),
                fingerprint_path_reference(&store_dir, &store_path, &nar_hash, nar_size, &references)
            );
        }
    }

    #[test]
    fn test_fingerprint_path() {
        let store_dir = StoreDir::new("/nix/store").unwrap();
        let store_path =
            StorePath::from_bytes(b"syd87l2rxw8cbsxmxl853h0r6pdwhwjr-curl-7.82.0-bin").unwrap();
        let nar_hash: NarHash = "sha256:1b4sb93wp679q4zx9k1ignby1yna3z7c4c2ri3wphylbc2dwsys0"
            .parse::<Base32<NarHash>>()
            .unwrap()
            .into_hash();
        let mut references = BTreeSet::new();
        references.insert(
            StorePath::from_bytes(b"0jqd0rlxzra1rs38rdxl43yh6rxchgc6-curl-7.82.0").unwrap(),
        );
        let fingerprint = fingerprint_path(&store_dir, &store_path, &nar_hash, 196040, &references);
        let expected = b"1;/nix/store/syd87l2rxw8cbsxmxl853h0r6pdwhwjr-curl-7.82.0-bin;sha256:1b4sb93wp679q4zx9k1ignby1yna3z7c4c2ri3wphylbc2dwsys0;196040;/nix/store/0jqd0rlxzra1rs38rdxl43yh6rxchgc6-curl-7.82.0";
        assert_eq!(fingerprint, expected);

        let fingerprint = fingerprint_path(&store_dir, &store_path, &nar_hash, 0, &BTreeSet::new());
        let expected = b"1;/nix/store/syd87l2rxw8cbsxmxl853h0r6pdwhwjr-curl-7.82.0-bin;sha256:1b4sb93wp679q4zx9k1ignby1yna3z7c4c2ri3wphylbc2dwsys0;0;";
        assert_eq!(fingerprint, expected);
    }
}
