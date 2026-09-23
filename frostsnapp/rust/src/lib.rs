pub mod api;
mod coordinator;
mod device_list;
#[allow(clippy::all)]
mod frb_generated;
pub mod logger;
pub mod sink_wrap;
/// Dev/test-only chain fixtures and an independent Taproot signature check for the
/// cold-snap app rig. Not in `api/`, for the same reason as `test_serial`: the two bridge
/// functions that reach it are `api::SuperWallet::test_inject_funding` and
/// `api::SuperWallet::verify_taproot_signatures`.
pub mod test_chain;
/// Dev/test-only pty transport for the cold-snap app rig. Not in `api/`, so it adds
/// nothing to the Dart bridge surface: the one bridge function that selects it is
/// `api::Api::load_test_pty_serial`.
pub mod test_serial;

pub use bitcoin::Network;
use frostsnap_coordinator::FirmwareBin;
pub use frostsnap_core::device::KeyPurpose;
use frostsnap_core::SymmetricKey;

#[cfg(not(bundle_firmware))]
pub const FIRMWARE: Option<FirmwareBin> = None;

#[cfg(bundle_firmware)]
pub const FIRMWARE: Option<FirmwareBin> = Some(FirmwareBin::new(include_bytes!(concat!(
    env!("OUT_DIR"),
    "/firmware.bin"
))));

#[allow(unused)]
/// meant to be replaced by something that's actually secure from the phone's secure element.
const TEMP_KEY: SymmetricKey = SymmetricKey([42u8; 32]);
