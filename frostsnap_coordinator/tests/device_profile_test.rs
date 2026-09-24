//! The compatibility/capability model, and the upgrade protocol's device set.
//!
//! Every digest here comes from a labelled source: the ESP32 ones from the
//! `v0.0.1-firmware-*.bin` fixtures beside this file, the Mk4 ones from
//! `src/coldsnap-mk4-registry.txt` itself. Nothing is a bare literal.

use frostsnap_comms::{CoordinatorSendBody, Destination, Sha256Digest};
use frostsnap_coordinator::{
    firmware_upgrade::FirmwareUpgradeProtocol, Completion, DeviceCapabilities, DeviceProfile,
    FactoryAttestation, FirmwareBin, FirmwareFeatures, FirmwareUpgradeEligibility, FirmwareVersion,
    UiProtocol, ValidatedFirmwareBin,
};
use frostsnap_core::DeviceId;
use std::collections::{BTreeSet, HashMap};

/// A real signed ESP32 v0.0.1 release, as the app would bundle it.
fn esp32_bundle() -> ValidatedFirmwareBin {
    FirmwareBin::new(include_bytes!("v0.0.1-firmware-signed.bin"))
        .validate()
        .expect("fixture is a valid firmware image")
}

/// The first registered cold-snap Mk4 revision, read from the registry so the test
/// cannot drift from the data it is about.
fn registered_mk4() -> (Sha256Digest, &'static str) {
    let line = include_str!("../src/coldsnap-mk4-registry.txt")
        .lines()
        .find(|line| !line.starts_with('#') && line.contains(' '))
        .expect("the registry has at least one entry");
    let (digest, label) = line.split_once(' ').unwrap();
    (digest.parse().expect("registry holds a sha256"), label)
}

/// Not a release, not registered, not the bundled image.
const UNKNOWN: Sha256Digest = Sha256Digest([0xab; 32]);

fn device(n: u8) -> DeviceId {
    DeviceId([n; 33])
}

/// THE FAIL-OPEN THIS MODEL EXISTS TO CLOSE. `FirmwareVersion::features()` used to
/// answer `FirmwareFeatures::all()` for any digest it did not recognize, so an
/// unknown device got every feature by accident of being unknown.
#[test]
fn an_unknown_digest_claims_no_feature_and_no_capability() {
    let profile = DeviceProfile::identify(UNKNOWN, Some(esp32_bundle().digest()));
    assert_eq!(profile, DeviceProfile::Unrecognized);
    assert!(!profile.is_compatible());
    assert_eq!(profile.features(), FirmwareFeatures::default());
    assert_ne!(
        profile.features(),
        FirmwareFeatures::all(),
        "an unrecognized digest must never inherit every feature"
    );
    let caps = profile.capabilities();
    assert!(!caps.backup && !caps.erase && !caps.update_mode);
    assert_eq!(caps.factory_attestation, FactoryAttestation::Unsupported);
    assert_eq!(caps.max_keygen_devices, None);
    assert!(profile.name(&UNKNOWN).starts_with("unrecognized-"));
}

/// A native release keeps its released identity and its released features, whether
/// or not the app bundles anything.
#[test]
fn a_known_esp32_release_is_compatible_with_no_bundled_firmware() {
    let release = esp32_bundle().digest();
    let with_bundle = DeviceProfile::identify(release, Some(release));
    let without_bundle = DeviceProfile::identify(release, None);

    assert_eq!(
        with_bundle, without_bundle,
        "recognition of a release must not depend on what the app happens to bundle"
    );
    assert_eq!(
        without_bundle,
        DeviceProfile::Esp32Frostsnap {
            release: Some(frostsnap_coordinator::VersionNumber::new(0, 0, 1))
        }
    );
    assert!(without_bundle.is_compatible());
    assert!(without_bundle.capabilities().update_mode);
    assert_eq!(without_bundle.name(&release), "v0.0.1");
    // v0.0.1 predates digest-only upgrades, and still says so.
    assert!(!without_bundle.features().upgrade_digest_no_sig);
}

/// The exact image the app bundles is recognized as ESP32 even when it is a
/// development build with no released version. Recognized because it is
/// byte-for-byte our image, NOT because its digest is unknown.
#[test]
fn the_exact_bundled_development_image_is_recognized() {
    let dev_digest = UNKNOWN;
    let profile = DeviceProfile::identify(dev_digest, Some(dev_digest));
    assert_eq!(profile, DeviceProfile::Esp32Frostsnap { release: None });
    assert!(profile.is_compatible());
    assert_eq!(
        profile.features(),
        FirmwareFeatures::all(),
        "our own build gets the features this tree implements"
    );
    assert!(profile.name(&dev_digest).starts_with("esp32-dev-"));
}

/// Criterion 1, the Rust half: usable with NO bundled Mk4 image and no ESP32
/// digest match.
#[test]
fn a_registered_mk4_is_compatible_without_any_bundled_image() {
    let (digest, label) = registered_mk4();

    for bundled in [None, Some(esp32_bundle().digest())] {
        let profile = DeviceProfile::identify(digest, bundled);
        assert_eq!(
            profile,
            DeviceProfile::ColdsnapMk4 {
                revision: label.to_string()
            },
            "registration must not depend on the app's bundled image"
        );
        assert!(profile.is_compatible());
        assert_eq!(profile.name(&digest), format!("mk4 {label}"));
    }
}

/// Capabilities differ by hardware, and are not a feature flag inherited from an
/// ESP32 identity.
#[test]
fn mk4_and_esp32_capabilities_differ() {
    let (mk4_digest, _) = registered_mk4();
    let mk4 = DeviceProfile::identify(mk4_digest, None).capabilities();
    let esp32 = DeviceProfile::identify(esp32_bundle().digest(), None).capabilities();

    let DeviceCapabilities {
        backup,
        erase,
        update_mode,
        factory_attestation,
        max_keygen_devices,
        features,
        host_image_update,
    } = mk4;
    assert!(
        host_image_update,
        "the Mk4 takes an image file through its own upgrade listener"
    );
    assert!(
        !esp32.host_image_update,
        "the ESP32 is upgraded through update_mode, never the Mk4 listener path"
    );
    assert!(backup, "the Mk4 displays and accepts a physical backup");
    assert!(features.check_backup, "and answers the check-backup quiz");
    assert!(!erase, "DataErase is refused: Refusal::DataErase");
    assert!(
        !update_mode,
        "every CoordinatorUpgradeMessage is refused: Refusal::FirmwareUpgrade"
    );
    assert_eq!(
        factory_attestation,
        FactoryAttestation::Unsupported,
        "no DS peripheral and no factory certificate: Refusal::GenuineChallenge"
    );
    assert_eq!(max_keygen_devices, Some(12), "declared support envelope");

    assert!(esp32.erase && esp32.update_mode);
    assert_eq!(esp32.factory_attestation, FactoryAttestation::NotChecked);
    assert_ne!(
        esp32.factory_attestation,
        FactoryAttestation::Unsupported,
        "the ESP32 could answer a challenge; this build just does not ask"
    );
    assert_eq!(
        esp32.max_keygen_devices, None,
        "no ESP32 profile declares a ceiling, so it must not borrow the Mk4's"
    );
}

/// An ESP32 image is never offered to an Mk4 — the `(None, None) => CanUpgrade`
/// arm used to swallow it, because neither digest resolves to a version.
#[test]
fn an_esp32_image_is_not_offered_to_a_registered_mk4() {
    let (mk4_digest, label) = registered_mk4();

    // A development app: bundled image has no released version, which is exactly
    // the case that used to answer CanUpgrade.
    let dev_app = FirmwareVersion::new(UNKNOWN);
    match dev_app.check_upgrade_eligibility(&mk4_digest) {
        FirmwareUpgradeEligibility::CannotUpgrade { reason } => {
            assert!(
                reason.contains(label),
                "the reason should name the revision"
            );
        }
        other => panic!("a dev app offered an ESP32 image to an Mk4: {other:?}"),
    }

    // A released app refuses it too.
    let released_app = FirmwareVersion::new(esp32_bundle().digest());
    assert!(matches!(
        released_app.check_upgrade_eligibility(&mk4_digest),
        FirmwareUpgradeEligibility::CannotUpgrade { .. }
    ));

    // And the native paths are untouched: the exact bundled image is up to date,
    // an older release can upgrade.
    assert_eq!(
        released_app.check_upgrade_eligibility(&esp32_bundle().digest()),
        FirmwareUpgradeEligibility::UpToDate
    );
    assert_eq!(
        dev_app.check_upgrade_eligibility(&UNKNOWN),
        FirmwareUpgradeEligibility::UpToDate
    );
}

fn upgrade_protocol(devices: &[(DeviceId, Sha256Digest)]) -> FirmwareUpgradeProtocol {
    let devices: HashMap<_, _> = devices
        .iter()
        .map(|(id, digest)| (*id, FirmwareVersion::new(*digest)))
        .collect();
    FirmwareUpgradeProtocol::new(devices, BTreeSet::new(), esp32_bundle(), ())
}

/// Criterion 3, the protocol half. `is_complete` requires a passive
/// `AckUpgradeMode` from EVERY device in the set, so any device left in it that
/// cannot ack blocks the upgrade forever. A cold-snap Mk4 is exactly that: its
/// upgrade listener has no `DeviceId` at all, so the ack cannot be sent even in
/// principle. That is why `esp32_upgrade_devices` filters before the protocol is
/// built rather than after.
#[test]
fn the_protocol_waits_for_an_ack_from_every_device_in_its_set() {
    let esp32 = device(1);
    let other = device(2);
    let mk4 = device(3);
    let bundled = esp32_bundle().digest();

    // The filtered set: one device in, and its passive ack completes it.
    let mut filtered = upgrade_protocol(&[(esp32, bundled)]);
    assert!(filtered.is_complete().is_none(), "nothing has acked yet");
    assert!(filtered.process_comms_message(esp32, frostsnap_comms::CommsMisc::AckUpgradeMode));
    assert!(
        matches!(filtered.is_complete(), Some(Completion::Success)),
        "the one selected device acked, so the upgrade is ready"
    );

    // A second device in the set that does not ack holds the whole upgrade.
    let mut wider = upgrade_protocol(&[(esp32, bundled), (other, bundled)]);
    assert!(wider.process_comms_message(esp32, frostsnap_comms::CommsMisc::AckUpgradeMode));
    assert!(
        wider.is_complete().is_none(),
        "a device in the set that never acks blocks the upgrade"
    );

    // Unplugging a device that was never selected does not abort the upgrade.
    let mut filtered = upgrade_protocol(&[(esp32, bundled)]);
    filtered.disconnected(mk4);
    assert!(filtered.is_complete().is_none());
    assert!(filtered.process_comms_message(esp32, frostsnap_comms::CommsMisc::AckUpgradeMode));
    assert!(matches!(filtered.is_complete(), Some(Completion::Success)));
}

/// The second barrier, in case a caller ever hands the protocol an Mk4 anyway: the
/// registered digest is now `CannotUpgrade`, which the protocol turns into an abort
/// on construction. A stopped upgrade with a reason, not a silent wait.
#[test]
fn an_mk4_left_in_the_upgrade_set_aborts_instead_of_hanging() {
    let (mk4_digest, _) = registered_mk4();
    let protocol = upgrade_protocol(&[
        (device(1), esp32_bundle().digest()),
        (device(2), mk4_digest),
    ]);
    assert!(matches!(
        protocol.is_complete(),
        Some(Completion::Abort { .. })
    ));
}

/// The `PrepareUpgrade`/`PrepareUpgrade2` message is addressed, not broadcast.
#[test]
fn the_prepare_upgrade_message_names_its_recipients() {
    let esp32 = device(1);
    let mk4 = device(2);
    let mut protocol = upgrade_protocol(&[(esp32, esp32_bundle().digest())]);

    let sent = protocol.poll();
    assert_eq!(sent.len(), 1);
    assert!(matches!(
        sent[0].message_body,
        CoordinatorSendBody::Upgrade(_)
    ));
    match &sent[0].target_destinations {
        Destination::Particular(ids) => {
            assert!(ids.contains(&esp32));
            assert!(
                !ids.contains(&mk4),
                "a device outside the set must not be addressed"
            );
        }
        Destination::All => panic!("upgrade messages must not be broadcast to every device"),
    }
}

/// Protocol selection is computed over the selected devices only, so a device
/// outside the set cannot decide which upgrade message its peers receive. The
/// native v0.0.1 path — a release that predates `upgrade_digest_no_sig` and so
/// needs the legacy message — still gets it.
#[test]
fn legacy_protocol_selection_follows_the_selected_devices() {
    let mut protocol = upgrade_protocol(&[(device(1), esp32_bundle().digest())]);
    let sent = protocol.poll();
    assert!(
        matches!(
            sent[0].message_body,
            CoordinatorSendBody::Upgrade(
                frostsnap_comms::CoordinatorUpgradeMessage::PrepareUpgrade { .. }
            )
        ),
        "a v0.0.1 device needs the legacy message"
    );
}

/// THE ASSERTION THE SUITE WAS MISSING. Message selection used to be
/// `!features().upgrade_digest_no_sig`, which is `true` for `Unrecognized` — so a
/// native ESP32 flashed from a different tree state than the app's bundle, i.e.
/// exactly the population that *needs* the upgrade in a development app, was put
/// on the legacy dialect. That announces the SIGNED digest, and `device/src/ota.rs`
/// accepts only the body digest, so every device refused the image.
///
/// Both tests above land on the legacy arm with a v0.0.1 device, where old and new
/// behaviour agree. This is the case where they do not.
#[test]
fn only_a_release_that_predates_the_modern_message_takes_the_legacy_dialect() {
    let bundled = esp32_bundle().digest();
    let (mk4, _) = registered_mk4();

    // v0.0.1: the one release that legitimately needs it.
    assert!(
        DeviceProfile::identify(bundled, Some(bundled)).needs_legacy_upgrade_message(),
        "v0.0.1 predates upgrade_digest_no_sig"
    );

    // Everything we cannot identify as that release must not get it.
    for (digest, bundle, what) in [
        (UNKNOWN, Some(UNKNOWN), "our own bundled development image"),
        (
            UNKNOWN,
            Some(bundled),
            "an ESP32 built from another tree state",
        ),
        (
            UNKNOWN,
            None,
            "an unknown device in an app bundling nothing",
        ),
        (mk4, None, "a registered Mk4"),
    ] {
        let profile = DeviceProfile::identify(digest, bundle);
        assert!(
            !profile.needs_legacy_upgrade_message(),
            "{what} is not a pre-0.0.2 release and must not be sent the signed digest"
        );
    }
}

/// And the protocol carries the BODY digest on that arm, which is the byte-level
/// half of the same regression: the legacy variant carries
/// `digest_with_signature()`, and for a signed bundle the two differ.
#[test]
fn the_modern_message_announces_the_body_digest() {
    let bundle = esp32_bundle();
    assert_ne!(
        bundle.digest(),
        bundle.digest_with_signature(),
        "the fixture is signed, so picking the wrong variant announces the wrong bytes"
    );

    let mut protocol = upgrade_protocol(&[]);
    let sent = protocol.poll();
    match &sent[0].message_body {
        CoordinatorSendBody::Upgrade(
            frostsnap_comms::CoordinatorUpgradeMessage::PrepareUpgrade2 {
                firmware_digest, ..
            },
        ) => assert_eq!(
            *firmware_digest,
            bundle.digest(),
            "device/src/ota.rs accepts only the body digest"
        ),
        other => panic!("expected PrepareUpgrade2, got {other:?}"),
    }
}

/// Check-backup follows the same rule, and for the same reason: the legacy arm asks
/// the human to retype all 25 words instead of letting the device sit the quiz.
#[test]
fn only_a_release_that_predates_check_backup_takes_the_legacy_backup_flow() {
    let bundled = esp32_bundle().digest();
    let (mk4, _) = registered_mk4();

    assert!(
        DeviceProfile::identify(bundled, None).needs_legacy_check_backup(),
        "v0.0.1 predates CheckBackup"
    );
    for (digest, bundle) in [
        (UNKNOWN, Some(UNKNOWN)),
        (UNKNOWN, Some(bundled)),
        (UNKNOWN, None),
        (mk4, None),
    ] {
        assert!(
            !DeviceProfile::identify(digest, bundle).needs_legacy_check_backup(),
            "an unidentified digest is not evidence that the firmware predates the quiz"
        );
    }
}
