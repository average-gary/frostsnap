pub use crate::api::firmware::{FirmwareUpgradeEligibility, FirmwareVersion};
use anyhow::Result;
use flutter_rust_bridge::frb;
use frostsnap_coordinator::{DeviceCapabilities, DeviceMode, DeviceProfile};
use frostsnap_core::{AccessStructureRef, DeviceId};

use crate::{frb_generated::StreamSink, sink_wrap::SinkWrap};

#[derive(Clone, Debug)]
pub enum DeviceListChangeKind {
    Added,
    Removed,
    Named,
    RecoveryMode,
}

#[derive(Clone, Debug)]
pub struct DeviceListChange {
    pub kind: DeviceListChangeKind,
    pub index: u32,
    pub device: ConnectedDevice,
}

#[derive(Clone, Debug)]
pub struct DeviceListUpdate {
    pub changes: Vec<DeviceListChange>,
    pub state: DeviceListState,
}

#[derive(Clone, Debug)]
pub struct DeviceListState {
    pub devices: Vec<ConnectedDevice>,
    pub state_id: u32,
}

/// Whether a device is in recovery mode, and what it still has outstanding. The two are not
/// independent — pending consolidations only exist in recovery — so they are one value rather
/// than a bool beside a list that could disagree with it.
#[derive(Clone, Debug, PartialEq)]
pub enum RecoveryMode {
    Off,
    On {
        /// Wallets with DEFERRED consolidation work — the coordinator's
        /// `pending_physical_consolidations`, i.e. work left over from restorations that have
        /// already finished. Non-empty is the re-plug discovery the background auto-exit acts
        /// on, resolving each wallet's key separately.
        ///
        /// EMPTY IS NORMAL, and it does **not** mean the device has nothing outstanding: an
        /// app-driven restoration can still have consolidation in flight via
        /// `tmp_waiting_consolidate`. It means only that there is no *deferred* work for the
        /// background auto-exit to pick up, because the active flow owns whatever it has in
        /// progress and takes the device back out of recovery itself.
        pending: Vec<AccessStructureRef>,
    },
}

#[derive(Clone, Debug)]
pub struct ConnectedDevice {
    pub name: Option<String>,
    pub firmware: FirmwareVersion,
    pub latest_firmware: Option<FirmwareVersion>,
    pub id: DeviceId,
    pub recovery_mode: RecoveryMode,
}

impl ConnectedDevice {
    /// Which firmware this device announced. The first of the three separate
    /// questions about a device's firmware; the others are [`Self::capabilities`]
    /// (what it can do) and [`Self::firmware_upgrade_eligibility`] (whether this
    /// app holds an update for it).
    #[frb(sync)]
    pub fn profile(&self) -> DeviceProfile {
        DeviceProfile::identify(
            self.firmware.digest,
            self.latest_firmware.map(|firmware| firmware.digest),
        )
    }

    /// Whether the app can work with this device at all — NOT whether an update
    /// for it exists. A recognized cold-snap Mk4 is compatible with no bundled Mk4
    /// image in the app, which is the whole point of separating the two.
    #[frb(sync)]
    pub fn is_compatible(&self) -> bool {
        self.profile().is_compatible()
    }

    #[frb(sync)]
    pub fn capabilities(&self) -> DeviceCapabilities {
        self.profile().capabilities()
    }

    /// Firmware label for display. Distinguishes hardware families, so an Mk4 and
    /// an ESP32 development build are not both `dev-xxxxxx`.
    #[frb(sync)]
    pub fn firmware_name(&self) -> String {
        self.profile().name(&self.firmware.digest)
    }

    /// Usable for wallet workflows: named, compatible, and not waiting on an
    /// update this app is holding for it.
    ///
    /// This used to be `name.is_some() && firmware_is_up_to_date()`, which made
    /// "the app has no image for you" mean "you are not ready" — so with no
    /// bundled firmware NO device was ever ready.
    #[frb(sync)]
    pub fn ready(&self) -> bool {
        self.name.is_some() && self.is_compatible() && !self.needs_firmware_upgrade()
    }

    /// Whether an upgrade is available *and* possible.
    ///
    /// False both when the device is current and when nothing can be done —
    /// no firmware bundled in the app, or a device newer than the app knows
    /// about. Those are not the same as "up to date", but offering the user an
    /// upgrade that would be refused is worse than saying nothing, so they are
    /// the same answer here. Callers that mean "is this device current" want
    /// [`firmware_is_up_to_date`] instead.
    #[frb(sync)]
    pub fn needs_firmware_upgrade(&self) -> bool {
        matches!(
            self.firmware_upgrade_eligibility(),
            FirmwareUpgradeEligibility::CanUpgrade
        )
    }

    #[frb(ignore)]
    pub(crate) fn firmware_is_up_to_date(&self) -> bool {
        matches!(
            self.firmware_upgrade_eligibility(),
            FirmwareUpgradeEligibility::UpToDate
        )
    }

    #[frb(sync)]
    pub fn firmware_upgrade_eligibility(&self) -> FirmwareUpgradeEligibility {
        let Some(latest_firmware) = &self.latest_firmware else {
            return FirmwareUpgradeEligibility::CannotUpgrade {
                reason: "No firmware available in app".to_string(),
            };
        };

        latest_firmware.check_upgrade_eligibility(&self.firmware.digest)
    }

    #[frb(ignore)]
    pub(crate) fn device_mode(&self) -> DeviceMode {
        if self.name.is_none() {
            DeviceMode::Blank
        } else if matches!(self.recovery_mode, RecoveryMode::On { .. }) {
            DeviceMode::Recovery
        } else {
            DeviceMode::Ready
        }
    }
}

/// The keygen party ceiling for a group: the smallest ceiling any participating
/// firmware declares, and which firmware declared it. `None` when no participant
/// declares one — a ceiling is a declared capability of the firmware taking part,
/// never a number the coordinator picked for it.
#[frb(ignore)]
pub(crate) fn keygen_ceiling(devices: &[ConnectedDevice]) -> Option<(u16, String)> {
    devices
        .iter()
        .filter_map(|device| {
            device
                .capabilities()
                .max_keygen_devices
                .map(|max| (max, device.firmware_name()))
        })
        .min()
}

/// The refusals `generate_new_key` applies before `BeginKeygen::new`: every
/// participant must be compatible, and the party count must be inside every
/// ceiling the participating firmware declares.
///
/// A FUNCTION SO THE REFUSAL ITSELF IS TESTABLE. Inline in `generate_new_key` it
/// was reachable only through an `FfiCoordinator` with a sqlite DB and a live
/// device list, so only the ceiling *arithmetic* ([`keygen_ceiling`]) had a test
/// and the rejection criterion 5 names had none.
///
/// `n_parties` is the number of devices the caller asked for — what `BeginKeygen`
/// will carry — and not `selected.len()`, so a request naming a device that is no
/// longer connected is not quietly counted short of the ceiling.
#[frb(ignore)]
pub(crate) fn check_keygen_group(
    selected: &[ConnectedDevice],
    n_parties: usize,
) -> anyhow::Result<()> {
    if let Some(device) = selected.iter().find(|device| !device.is_compatible()) {
        anyhow::bail!(
            "device {} runs unrecognized firmware ({}), so it cannot take part in a keygen",
            device.id,
            device.firmware_name()
        );
    }
    // The ceiling is a DECLARED CAPABILITY of the participating firmware, not a
    // number the coordinator picked: the smallest declared ceiling in the group
    // wins, and a profile that declares none does not impose one. Checked before
    // the keygen starts, because the device-side refusal
    // (`Refusal::GroupTooLarge`) is an ack that never arrives — there is nothing
    // to hear back.
    if let Some((max, firmware)) = keygen_ceiling(selected) {
        if n_parties > max as usize {
            anyhow::bail!(
                "{n_parties} devices selected but {firmware} declares a ceiling of {max}"
            );
        }
    }
    Ok(())
}

impl DeviceListState {
    #[frb(sync)]
    pub fn get_device(&self, id: DeviceId) -> Option<ConnectedDevice> {
        self.devices.iter().find(|device| device.id == id).cloned()
    }
}

impl super::coordinator::Coordinator {
    #[frb(sync)]
    pub fn device_at_index(&self, index: usize) -> Option<ConnectedDevice> {
        self.0.device_at_index(index)
    }

    #[frb(sync)]
    pub fn device_list_state(&self) -> DeviceListState {
        self.0.device_list_state()
    }

    pub fn sub_device_events(&self, sink: StreamSink<DeviceListUpdate>) -> Result<()> {
        self.0.sub_device_events(SinkWrap(sink));
        Ok(())
    }

    #[frb(sync)]
    pub fn get_connected_device(&self, id: DeviceId) -> Option<ConnectedDevice> {
        self.0.get_connected_device(id)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use frostsnap_coordinator::{FactoryAttestation, VersionNumber};

    /// The registry is read, not copied: a literal here could drift from the file
    /// the shipped code consults.
    fn mk4_digest() -> frostsnap_coordinator::frostsnap_comms::Sha256Digest {
        include_str!("../../../../frostsnap_coordinator/src/coldsnap-mk4-registry.txt")
            .lines()
            .find(|line| !line.starts_with('#') && line.contains(' '))
            .and_then(|line| line.split_once(' '))
            .expect("the registry has at least one entry")
            .0
            .parse()
            .expect("registry holds a sha256")
    }

    /// Not a release, not registered.
    fn unknown() -> frostsnap_coordinator::frostsnap_comms::Sha256Digest {
        frostsnap_coordinator::frostsnap_comms::Sha256Digest([0xcd; 32])
    }

    fn connected(
        digest: frostsnap_coordinator::frostsnap_comms::Sha256Digest,
        bundled: Option<frostsnap_coordinator::frostsnap_comms::Sha256Digest>,
    ) -> ConnectedDevice {
        ConnectedDevice {
            name: Some("device".into()),
            firmware: FirmwareVersion::new(digest),
            latest_firmware: bundled.map(FirmwareVersion::new),
            id: DeviceId([7; 33]),
            recovery_mode: RecoveryMode::Off,
        }
    }

    /// NO BUNDLED FIRMWARE. A recognized Mk4 is compatible, nameable and ready with
    /// no Mk4 image in the app — which used to be impossible, because "the app has
    /// no image for you" was the same answer as "you are incompatible".
    #[test]
    fn a_recognized_mk4_is_ready_with_no_bundled_firmware() {
        let device = connected(mk4_digest(), None);
        assert!(device.is_compatible());
        assert!(device.ready());
        assert!(!device.needs_firmware_upgrade());
        assert!(device.firmware_name().starts_with("mk4 "));
        assert!(matches!(
            device.profile(),
            DeviceProfile::ColdsnapMk4 { .. }
        ));
        // Update availability is the separate, third question, and it still says no.
        assert!(matches!(
            device.firmware_upgrade_eligibility(),
            FirmwareUpgradeEligibility::CannotUpgrade { .. }
        ));
    }

    /// And a bundled ESP32 image does not turn the Mk4 into an upgrade target.
    #[test]
    fn an_mk4_is_not_offered_the_bundled_esp32_image() {
        let device = connected(mk4_digest(), Some(unknown()));
        assert!(device.is_compatible());
        assert!(device.ready());
        assert!(
            !device.needs_firmware_upgrade(),
            "an ESP32 image must never be offered to an Mk4"
        );
    }

    /// UNSUPPORTED FIRMWARE stays explicit: not compatible, not ready, and named as
    /// unrecognized rather than as a development build.
    #[test]
    fn unrecognized_firmware_is_not_compatible() {
        let device = connected(unknown(), None);
        assert!(!device.is_compatible());
        assert!(!device.ready());
        assert_eq!(device.profile(), DeviceProfile::Unrecognized);
        assert!(device.firmware_name().starts_with("unrecognized-"));
        let caps = device.capabilities();
        assert!(!caps.erase && !caps.update_mode && !caps.backup);
    }

    /// NATIVE BEHAVIOUR: the exact bundled image is recognized and ready, and its
    /// eligibility is still `UpToDate`.
    #[test]
    fn the_bundled_esp32_image_is_ready() {
        let device = connected(unknown(), Some(unknown()));
        assert_eq!(
            device.profile(),
            DeviceProfile::Esp32Frostsnap { release: None }
        );
        assert!(device.is_compatible());
        assert!(device.ready());
        assert!(matches!(
            device.firmware_upgrade_eligibility(),
            FirmwareUpgradeEligibility::UpToDate
        ));
        assert!(device.capabilities().update_mode);
    }

    /// A device with no name is not ready however compatible it is.
    #[test]
    fn an_unnamed_device_is_not_ready() {
        let mut device = connected(mk4_digest(), None);
        device.name = None;
        assert!(device.is_compatible());
        assert!(!device.ready());
    }

    /// CAPABILITY DIFFERENCES are visible on the API the UI reads, so a refusal does
    /// not have to be inferred from an upgrade string.
    #[test]
    fn capability_differences_are_on_the_api() {
        let mk4 = connected(mk4_digest(), None).capabilities();
        let esp32 = connected(unknown(), Some(unknown())).capabilities();

        assert!(!mk4.erase, "the Mk4 refuses DataErase");
        assert!(esp32.erase);
        assert!(!mk4.update_mode, "the Mk4 refuses every upgrade message");
        assert!(
            mk4.host_image_update,
            "the Mk4 takes an image through its own upgrade listener"
        );
        assert!(!esp32.host_image_update, "the ESP32 path is update_mode's");
        assert_eq!(mk4.factory_attestation, FactoryAttestation::Unsupported);
        assert_eq!(esp32.factory_attestation, FactoryAttestation::NotChecked);
        assert!(
            mk4.features.check_backup,
            "the Mk4 does answer the check-backup quiz"
        );
    }

    /// THE KEYGEN CEILING is the smallest one any participant declares, and an
    /// all-native group has none. 12 comes from the Mk4's declared capability, not
    /// from a number written into the coordinator.
    #[test]
    fn the_keygen_ceiling_comes_from_the_participating_firmware() {
        let mk4 = connected(mk4_digest(), None);
        let esp32 = connected(unknown(), Some(unknown()));

        assert_eq!(keygen_ceiling(&[esp32.clone(), esp32.clone()]), None);
        let (max, firmware) = keygen_ceiling(&[esp32.clone(), mk4.clone()])
            .expect("the Mk4 declares a ceiling for the whole group");
        assert_eq!(max, 12);
        assert!(firmware.starts_with("mk4 "));
        assert_eq!(keygen_ceiling(&[]), None);

        // 12 is allowed, 13 is over: the bound the refusal has to be built against.
        let group: Vec<_> = std::iter::repeat_with(|| mk4.clone()).take(13).collect();
        let (max, _) = keygen_ceiling(&group).unwrap();
        assert!(12 <= max as usize && (13 > max as usize));
    }

    /// CRITERION 5's "rejection of an over-limit keygen before starting it". This is
    /// the refusal itself — the exact call `generate_new_key` makes before
    /// `BeginKeygen::new` — not the ceiling arithmetic, which
    /// `the_keygen_ceiling_comes_from_the_participating_firmware` covers.
    #[test]
    fn an_over_limit_keygen_is_refused_before_it_starts() {
        let mk4 = connected(mk4_digest(), None);
        let group =
            |n: usize| -> Vec<_> { std::iter::repeat_with(|| mk4.clone()).take(n).collect() };

        // 12 is inside the declared envelope.
        let twelve = group(12);
        check_keygen_group(&twelve, twelve.len()).expect("12 devices is within the Mk4 ceiling");

        // 13 is not, and the refusal names the ceiling and the firmware declaring it.
        let thirteen = group(13);
        let refusal = check_keygen_group(&thirteen, thirteen.len())
            .expect_err("13 devices is over the Mk4's declared ceiling of 12")
            .to_string();
        assert!(
            refusal.contains("13") && refusal.contains("12") && refusal.contains("mk4 "),
            "the refusal must say what was asked, what the ceiling is and who declared it: {refusal}"
        );

        // A group whose participants declare no ceiling is not given one.
        let esp32 = connected(unknown(), Some(unknown()));
        let native = vec![esp32.clone(), esp32.clone(), esp32];
        check_keygen_group(&native, 13)
            .expect("no participant declares a ceiling, so the coordinator imposes none");
    }

    /// The other half of the same refusal: unrecognized firmware cannot take part at
    /// all, checked in Rust so a direct bridge call cannot skip the UI's filter.
    #[test]
    fn unrecognized_firmware_is_refused_from_a_keygen() {
        let devices = vec![connected(mk4_digest(), None), connected(unknown(), None)];
        let refusal = check_keygen_group(&devices, devices.len())
            .expect_err("an unrecognized device must not join a keygen")
            .to_string();
        assert!(
            refusal.contains("unrecognized firmware"),
            "unexpected refusal: {refusal}"
        );
    }

    /// A released ESP32 keeps its released identity rather than being read as a
    /// development build.
    #[test]
    fn a_released_esp32_digest_keeps_its_version() {
        // v0.0.1's body digest, the one `frostsnap_comms` registers for it. Also
        // asserted against the real release artifact in
        // `frostsnap_coordinator/tests/device_profile_test.rs`.
        let v0_0_1: frostsnap_coordinator::frostsnap_comms::Sha256Digest =
            "8f45ae6b72c241a20798acbd3c6d3e54071cae73e335df1785f2d485a915da4c"
                .parse()
                .unwrap();
        let device = connected(v0_0_1, None);
        assert_eq!(
            device.profile(),
            DeviceProfile::Esp32Frostsnap {
                release: Some(VersionNumber::new(0, 0, 1))
            }
        );
        assert_eq!(device.firmware_name(), "v0.0.1");
        assert!(device.is_compatible());
    }
}
