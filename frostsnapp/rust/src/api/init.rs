use super::{
    coordinator::Coordinator, log::LogLevel, psbt_manager::PsbtManager, settings::Settings,
};
use crate::{
    coordinator::FfiCoordinator,
    frb_generated::{RustAutoOpaque, StreamSink},
};
use anyhow::{Context as _, Result};
use frostsnap_coordinator::{DesktopSerial, UsbSerialManager, ValidatedFirmwareBin};
use frostsnap_core::schnorr_fun::fun::{marker::EvenY, Point};
use std::{
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};
use tracing::{event, Level};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt, Registry};

impl super::Api {
    pub fn turn_logging_on(&self, level: LogLevel, log_stream: StreamSink<String>) -> Result<()> {
        // Global default subscriber must only be set once.
        if crate::logger::set_dart_logger(log_stream) {
            let targets = Targets::new()
                .with_target("nusb", Level::ERROR /* nusb makes spurious warnings */)
                .with_target("bdk_electrum_streaming", Level::WARN)
                .with_default(Level::from(level));

            #[cfg(not(target_os = "android"))]
            {
                let fmt_layer = tracing_subscriber::fmt::layer().without_time().pretty();

                Registry::default()
                    .with(targets.clone())
                    .with(fmt_layer)
                    .with(crate::logger::dart_logger())
                    .try_init()?;
            }

            #[cfg(target_os = "android")]
            {
                use tracing_logcat::{LogcatMakeWriter, LogcatTag};
                use tracing_subscriber::{fmt::format::Format, layer::Layer};

                let writer = LogcatMakeWriter::new(LogcatTag::Fixed("frostsnap/rust".to_owned()))
                    .expect("logcat writer");

                let fmt_layer = tracing_subscriber::fmt::layer()
                    .event_format(Format::default().with_target(true).without_time().compact())
                    .with_writer(writer)
                    .with_ansi(false)
                    .with_filter(targets.clone());

                Registry::default()
                    .with(targets.clone())
                    .with(fmt_layer)
                    .with(crate::logger::dart_logger())
                    .try_init()?;
            }

            event!(Level::INFO, "Rust tracing initialised");
        }
        Ok(())
    }

    // Android-specific function that returns FfiSerial
    pub fn load_host_handles_serial(
        &self,
        app_dir: String,
    ) -> Result<(Coordinator, AppCtx, super::port::FfiSerial)> {
        use super::port::FfiSerial;
        let app_dir = PathBuf::from_str(&app_dir)?;
        let ffi_serial = FfiSerial::default();
        let usb_manager = usb_serial_manager(Box::new(ffi_serial.clone()))?;
        let (coord, app_state) = load_internal(app_dir, usb_manager)?;
        Ok((coord, app_state, ffi_serial))
    }

    // Desktop function using DesktopSerial
    pub fn load(&self, app_dir: String) -> anyhow::Result<(Coordinator, AppCtx)> {
        let app_dir = PathBuf::from_str(&app_dir)?;
        load_internal(app_dir, usb_serial_manager(Box::new(DesktopSerial))?)
    }

    /// DEV/TEST ONLY: talk to the cold-snap app rig's pseudo-terminals instead of to
    /// USB, and to nothing else.
    ///
    /// A SEPARATE ENTRY POINT and not a flag on [`Self::load`], so production
    /// discovery is unchanged and unreachable from here, and so no environment
    /// variable can flip a shipped app onto a test transport. `port_manifest` is the
    /// `ports.txt` written by `cold-snap/tools/app-rig.py`; see
    /// `crate::test_serial::PtySerial` for the polarity and baud-rate traps it
    /// handles. Pass a disposable `app_dir`: both the sqlite DB and the bdk wallet
    /// files derive from it.
    pub fn load_test_pty_serial(
        &self,
        app_dir: String,
        port_manifest: String,
    ) -> anyhow::Result<(Coordinator, AppCtx)> {
        let app_dir = PathBuf::from_str(&app_dir)?;
        let manifest = PathBuf::from_str(&port_manifest)?;
        // FAIL LOUD at startup rather than enumerating zero ports forever: a typo'd
        // manifest path is indistinguishable from a rig that never came up.
        if !manifest.is_file() {
            anyhow::bail!(
                "no app rig port manifest at {} -- start cold-snap/tools/app-rig.py first",
                manifest.display()
            );
        }
        event!(
            Level::WARN,
            manifest = manifest.display().to_string(),
            "TEST TRANSPORT SELECTED: pty ports only, USB discovery is disabled"
        );
        let serial = crate::test_serial::PtySerial::new(manifest);
        load_internal(app_dir, usb_serial_manager(Box::new(serial))?)
    }
}

/// The manager configuration every entry point shares, so a test transport cannot
/// quietly differ from production in the firmware bin or the genuine-cert key it was
/// given. With `BUNDLE_FIRMWARE=0`, `crate::FIRMWARE` is `None` and no upgrade bin is
/// attached -- which is a supported configuration, not a compatibility bypass.
fn usb_serial_manager(serial: Box<dyn frostsnap_coordinator::Serial>) -> Result<UsbSerialManager> {
    let mut usb_manager = UsbSerialManager::new(serial);
    if let Some(firmware) = crate::FIRMWARE.map(ValidatedFirmwareBin::new).transpose()? {
        usb_manager = usb_manager.with_firmware_bin(firmware);
    }
    if let Some(key) = load_genuine_cert_key() {
        usb_manager = usb_manager.with_genuine_cert_key(key);
    }
    Ok(usb_manager)
}

#[cfg(genuine_cert_key)]
fn load_genuine_cert_key() -> Option<Point<EvenY>> {
    const HEX: &str = include_str!(concat!(env!("OUT_DIR"), "/genuine_cert_key.hex"));
    let bytes = frostsnap_core::hex::decode(HEX.trim()).ok()?;
    let array: [u8; 32] = bytes.try_into().ok()?;
    Point::<EvenY>::from_xonly_bytes(array)
}

#[cfg(not(genuine_cert_key))]
fn load_genuine_cert_key() -> Option<Point<EvenY>> {
    None
}

fn load_internal(
    app_dir: PathBuf,
    usb_serial_manager: UsbSerialManager,
) -> Result<(Coordinator, AppCtx)> {
    let db_file = app_dir.join("frostsnap.sqlite");
    event!(
        Level::INFO,
        path = db_file.display().to_string(),
        "initializing database"
    );
    let db = rusqlite::Connection::open(&db_file).with_context(|| {
        event!(
            Level::ERROR,
            path = db_file.display().to_string(),
            "failed to load database"
        );
        format!("failed to load database from {}", db_file.display())
    })?;
    let db = Arc::new(Mutex::new(db));

    let coordinator = FfiCoordinator::new(db.clone(), usb_serial_manager)?;
    let coordinator = Coordinator(coordinator);
    let app_state = AppCtx {
        settings: RustAutoOpaque::new(Settings::new(db.clone(), app_dir)?),
        psbt_manager: RustAutoOpaque::new(PsbtManager::new(db.clone())),
    };
    println!("loaded db");

    Ok((coordinator, app_state))
}

pub struct AppCtx {
    pub settings: RustAutoOpaque<Settings>,
    pub psbt_manager: RustAutoOpaque<PsbtManager>,
}

#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    // Default utilities - feel free to customize
    flutter_rust_bridge::setup_default_user_utils();
}
