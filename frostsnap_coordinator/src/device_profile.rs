//! What firmware a connected device runs, and what that firmware can do.
//!
//! THREE THINGS THAT USED TO BE ONE. Before this module the only answer the app
//! had about a device's firmware was [`FirmwareUpgradeEligibility`], so "can I
//! talk to this device", "what can it do" and "do I have an update for it" were
//! the same question — and a device with no update available came back
//! `CannotUpgrade`, which the UI renders as *incompatible*. They are separated
//! here:
//!
//! 1. **Protocol compatibility** — [`DeviceProfile`]. Which firmware is this?
//! 2. **Supported operations** — [`DeviceCapabilities`]. What will it do?
//! 3. **Update availability** — [`FirmwareUpgradeEligibility`], unchanged. Does
//!    this app hold an image this device can take?
//!
//! A [`DeviceProfile::ColdsnapMk4`] is compatible and usable with no bundled Mk4
//! image at all. That is the point.
//!
//! IDENTIFICATION IS BY ANNOUNCED DIGEST, AND A DIGEST IS INTEGRITY, NEVER TRUST.
//! The device reports it about itself over the same wire as everything else, so a
//! registry hit says WHICH FIRMWARE and nothing about WHO SENT IT. Recognition is
//! not attestation — see [`FactoryAttestation`], which has no success variant.

use crate::firmware::{FirmwareFeatures, VersionNumber};
use frostsnap_comms::Sha256Digest;

/// Which firmware a device announced. Three-valued on purpose: an unrecognized
/// digest is its own answer and never silently becomes a compatible one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceProfile {
    /// Native ESP32 Frostsnap. `release` is `None` for the exact development
    /// image this app bundles — recognized because it is byte-for-byte the image
    /// we hold, not because its digest is unknown.
    Esp32Frostsnap { release: Option<VersionNumber> },
    /// A cold-snap Mk4 build listed in `coldsnap-mk4-registry.txt`.
    ColdsnapMk4 { revision: String },
    /// Not a known release, not the bundled image, not a registered Mk4. Claims
    /// nothing on the device's behalf.
    Unrecognized,
}

impl DeviceProfile {
    /// Identify the firmware announcing `digest`. `bundled` is the digest of the
    /// ESP32 image this app ships, if it ships one.
    ///
    /// Order matters: a released ESP32 version wins, then the Mk4 registry, then
    /// byte equality with our own bundled development image. Nothing falls
    /// through to a compatible answer.
    pub fn identify(digest: Sha256Digest, bundled: Option<Sha256Digest>) -> Self {
        if let Some(release) = VersionNumber::from_digest(&digest) {
            return DeviceProfile::Esp32Frostsnap {
                release: Some(release),
            };
        }
        if let Some(revision) = registered_mk4_revision(&digest) {
            return DeviceProfile::ColdsnapMk4 {
                revision: revision.to_string(),
            };
        }
        if bundled == Some(digest) {
            return DeviceProfile::Esp32Frostsnap { release: None };
        }
        DeviceProfile::Unrecognized
    }

    /// Whether this app knows how to talk to this firmware at all. Independent of
    /// whether an update for it exists.
    pub fn is_compatible(&self) -> bool {
        !matches!(self, DeviceProfile::Unrecognized)
    }

    /// The wire-protocol feature flags, from the identified profile.
    ///
    /// THE OLD `FirmwareVersion::features()` FAILED OPEN HERE: an unknown digest
    /// returned [`FirmwareFeatures::all`], so a device got every feature by
    /// accident of not being recognized. Nothing below does that — an
    /// unrecognized profile claims no feature.
    pub fn features(&self) -> FirmwareFeatures {
        match self {
            // Our own build. Its features are the ones this tree implements.
            DeviceProfile::Esp32Frostsnap { release: None } => FirmwareFeatures::all(),
            DeviceProfile::Esp32Frostsnap {
                release: Some(version),
            } => version.features(),
            DeviceProfile::ColdsnapMk4 { .. } => FirmwareFeatures {
                // Unreachable for this profile: the flag only picks between
                // `PrepareUpgrade` and `PrepareUpgrade2`, and an Mk4 accepts
                // neither (`update_mode: false` below). Message selection asks
                // [`Self::needs_legacy_upgrade_message`], not this flag.
                upgrade_digest_no_sig: true,
                // `CoordinatorRestoration::CheckBackup` is admitted and drives
                // the quiz (cold-snap `firmware/src/lib.rs:1239`).
                check_backup: true,
            },
            DeviceProfile::Unrecognized => FirmwareFeatures::default(),
        }
    }

    /// Whether this device must be sent the legacy `CoordinatorUpgradeMessage::
    /// PrepareUpgrade`, which announces the image's digest *including* its
    /// signature, instead of `PrepareUpgrade2`, which announces the body digest.
    ///
    /// UNKNOWN IS NOT OLD, AND THE WRONG ANSWER HERE IS FATAL RATHER THAN
    /// COSMETIC. This is a protocol-dialect selector, not a permission: a device
    /// at or above v0.0.2 accepts only the body digest
    /// (`device/src/ota.rs`, `RefuseReason::DigestMismatch`), so announcing the
    /// signed digest to it means every device refuses the image. Asking
    /// `features().upgrade_digest_no_sig` instead put `Unrecognized` — which is
    /// what an ESP32 flashed from a different tree state than the app's bundle
    /// identifies as — on the legacy dialect and broke the default `just run`
    /// upgrade. So legacy is OPT-IN BY POSITIVE IDENTIFICATION: only a release we
    /// recognize as predating the modern message gets it. That is not a
    /// `FirmwareFeatures::all()` fallback — `features()` and `capabilities()` both
    /// still claim nothing at all for an unrecognized digest.
    pub fn needs_legacy_upgrade_message(&self) -> bool {
        match self {
            DeviceProfile::Esp32Frostsnap {
                release: Some(version),
            } => !version.features().upgrade_digest_no_sig,
            _ => false,
        }
    }

    /// Whether check-backup must use the legacy flow — `expected_share_image` plus
    /// `tell_device_to_load_physical_backup`, which asks the HUMAN to retype the
    /// whole 25-word backup — instead of the modern 3-option quiz the device sits
    /// by itself.
    ///
    /// Same rule and same reason as [`Self::needs_legacy_upgrade_message`]: the
    /// legacy arm is a downgrade of the user's flow, so choosing it requires
    /// positive knowledge that the firmware predates `CheckBackup`. Reading
    /// `features().check_backup` sent every `Unrecognized` device — i.e. every
    /// native ESP32 not byte-identical to the bundled image, and every device at
    /// all when the app bundles none — down the 25-word path.
    pub fn needs_legacy_check_backup(&self) -> bool {
        match self {
            DeviceProfile::Esp32Frostsnap {
                release: Some(version),
            } => !version.features().check_backup,
            _ => false,
        }
    }

    /// What operations this firmware supports.
    pub fn capabilities(&self) -> DeviceCapabilities {
        match self {
            DeviceProfile::Esp32Frostsnap { .. } => DeviceCapabilities {
                features: self.features(),
                backup: true,
                erase: true,
                update_mode: true,
                host_image_update: false,
                factory_attestation: FactoryAttestation::NotChecked,
                max_keygen_devices: None,
            },
            DeviceProfile::ColdsnapMk4 { .. } => DeviceCapabilities {
                features: self.features(),
                // `DisplayBackup`, the restore flow and `CheckBackup` are all
                // admitted (cold-snap `firmware/src/lib.rs:1136,1184,1239`).
                backup: true,
                // `CoordinatorSendBody::DataErase` is refused —
                // `Refusal::DataErase`, cold-snap `firmware/src/lib.rs:1071`.
                erase: false,
                // All three `CoordinatorUpgradeMessage` variants are refused —
                // `Refusal::FirmwareUpgrade`, cold-snap
                // `firmware/src/lib.rs:1070`. The Mk4 upgrade path is entered by
                // a physical key hold on the device, not by this app.
                update_mode: false,
                // Its pre-Session listener (cold-snap `firmware/src/upgrade.rs`
                // `run`, entered by holding OK at power-up) stages a checked image.
                host_image_update: true,
                // `CoordinatorSendBody::Challenge` is refused: no ESP32 DS
                // peripheral and no factory certificate (cold-snap
                // `firmware/src/lib.rs:184-187,1072`).
                factory_attestation: FactoryAttestation::Unsupported,
                // Declared support envelope: n <= 12 devices, any t <= n. The
                // device enforces its own half — `MAX_PARTIES = 12` at cold-snap
                // `firmware/src/lib.rs:291`, refused as `Refusal::GroupTooLarge`
                // — and a refusal on that wire is an ack that never arrives, so
                // the coordinator has to hold the same number rather than wait
                // for one. NOT a frame limit: 13-of-13 fits the frame and is
                // outside the envelope on purpose.
                max_keygen_devices: Some(12),
            },
            DeviceProfile::Unrecognized => DeviceCapabilities {
                features: FirmwareFeatures::default(),
                backup: false,
                erase: false,
                update_mode: false,
                host_image_update: false,
                factory_attestation: FactoryAttestation::Unsupported,
                max_keygen_devices: None,
            },
        }
    }

    /// Short label for the device's firmware, distinguishing hardware families so
    /// an Mk4 and an ESP32 development build are not both `dev-xxxxxx`.
    pub fn name(&self, digest: &Sha256Digest) -> String {
        match self {
            DeviceProfile::Esp32Frostsnap {
                release: Some(version),
            } => format!("v{version}"),
            DeviceProfile::Esp32Frostsnap { release: None } => {
                format!("esp32-dev-{}", short_hash(digest))
            }
            DeviceProfile::ColdsnapMk4 { revision } => format!("mk4 {revision}"),
            DeviceProfile::Unrecognized => format!("unrecognized-{}", short_hash(digest)),
        }
    }
}

fn short_hash(digest: &Sha256Digest) -> String {
    frostsnap_core::hex::encode(&digest.0[..3])
}

/// What a device will do, from its [`DeviceProfile`]. Separate from update
/// availability: every field here is true or false whether or not this app holds
/// an image for the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCapabilities {
    /// Wire-protocol feature flags.
    pub features: FirmwareFeatures,
    /// Displays and accepts a physical backup.
    pub backup: bool,
    /// Accepts `CoordinatorSendBody::DataErase`.
    pub erase: bool,
    /// Accepts the coordinator's firmware-upgrade messages and raw chunk stream.
    /// False means this app has no way to update the device and must not send it
    /// upgrade bytes — not that the device cannot be updated at all.
    pub update_mode: bool,
    /// Takes a checked image file from this host through its own upgrade
    /// listener (`UsbSerialManager::run_mk4_upgrade`), entered on the device and
    /// addressed by port, never through `update_mode`'s device-keyed flow.
    pub host_image_update: bool,
    pub factory_attestation: FactoryAttestation,
    /// Declared keygen party ceiling. `None` means this profile declares none.
    pub max_keygen_devices: Option<u16>,
}

/// Whether a factory attestation can be asked for. **There is deliberately no
/// success variant**: nothing in this tree produces one. The genuine check is
/// disabled coordinator-side (`usb_serial_manager.rs`, `DO_GENUINE_CHECK`) and no
/// refusal site exists, so a "passed" value here could only ever be a fake one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryAttestation {
    /// This firmware has no factory attestation to ask for.
    Unsupported,
    /// The profile could answer a challenge, but this build does not check one.
    /// NOT a pass, and must never be displayed as one.
    NotChecked,
}

/// Registered cold-snap Mk4 revisions: `(announced digest, label)`.
///
/// Parsed rather than `hex!`-ed into a const so registration is a line in a data
/// file — see `tools/register-mk4-firmware.py`. `registry_is_well_formed` is what
/// makes up for losing the compile-time parse.
fn registry_entries() -> impl Iterator<Item = (&'static str, &'static str)> {
    include_str!("coldsnap-mk4-registry.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once(' '))
        .map(|(digest, label)| (digest.trim(), label.trim()))
}

/// The registered revision announcing `digest`, if any.
pub fn registered_mk4_revision(digest: &Sha256Digest) -> Option<&'static str> {
    let hex = frostsnap_core::hex::encode(&digest.0);
    registry_entries()
        .find(|(entry, _)| *entry == hex)
        .map(|(_, label)| label)
}

#[cfg(test)]
mod test {
    use super::*;

    /// The registry is text, so its shape is a test rather than a compile error.
    #[test]
    fn registry_is_well_formed() {
        let entries: Vec<_> = registry_entries().collect();
        assert!(!entries.is_empty(), "registry parsed to nothing");
        for (digest, label) in &entries {
            assert_eq!(digest.len(), 64, "{digest} is not 64 hex chars");
            assert!(
                digest
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "{digest} is not lowercase hex"
            );
            assert!(!label.is_empty(), "{digest} has no revision label");
            assert!(
                !label.contains(char::is_whitespace),
                "{label} has whitespace in it"
            );
        }
        let mut digests: Vec<_> = entries.iter().map(|(d, _)| *d).collect();
        digests.sort_unstable();
        let before = digests.len();
        digests.dedup();
        assert_eq!(before, digests.len(), "a digest is registered twice");
    }

    /// Every registered digest resolves, and resolves to the Mk4 profile — not to
    /// an ESP32 release identity.
    #[test]
    fn registered_digests_identify_as_mk4() {
        for (hex, label) in registry_entries() {
            let digest: Sha256Digest = hex.parse().expect("registry holds a sha256");
            assert_eq!(registered_mk4_revision(&digest), Some(label));
            assert_eq!(
                DeviceProfile::identify(digest, None),
                DeviceProfile::ColdsnapMk4 {
                    revision: label.to_string()
                },
                "{label} did not identify as an Mk4"
            );
        }
    }
}
