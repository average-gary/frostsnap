//! DEV/TEST-ONLY transport: the cold-snap app rig's pseudo-terminals, and nothing else.
//!
//! Selected by its own entry point (`api::Api::load_test_pty_serial`), never by
//! `load()`. Production discovery (`DesktopSerial`) is untouched, and there is NO
//! fallback from here to physical USB: if a port is not in the rig's manifest this
//! impl will not open it, so a rig run cannot silently end up talking to a device on
//! somebody's desk.
//!
//! `FfiSerial` (`api/port.rs`) is not an alternative: it is `cfg(linux|android)` and
//! panics on macOS, and its fd path expects a raw USB device for `CdcAcmSerial`.
//!
//! The rig side is `cold-snap/tools/app-rig.py`: it opens one pty per virtual device,
//! hands the MASTER to a `firmware/examples/stub` child as fd 0/fd 1, holds a slave fd
//! open, and lists the slave paths in the manifest this file reads. The app must be on
//! the SLAVE: `FramedSerialPort::anything_to_read()` is FIONREAD, and FIONREAD on a
//! Darwin pty master always returns 0, so a coordinator on the master reads nothing
//! forever (cold-snap HARNESS-PLAN phase C.3, MEASURED).

use frostsnap_coordinator::{serialport, PortDesc, PortOpenError, Serial, SerialPort};
use std::{path::PathBuf, time::Duration};
use tracing::{event, Level};

/// The VID/PID `UsbSerialManager::poll_ports` filters on. They are private consts in
/// `frostsnap_coordinator::usb_serial_manager`, so they are restated here — as
/// `frostsnap_coordinator/tests/mock_port_upgrade_routing.rs` already does — rather
/// than widening the coordinator's API for a test transport. A pty has no USB
/// descriptor, so these are the rig declaring itself a cold-snap device.
const USB_VID: u16 = 12346;
const USB_PID: u16 = 4097;

/// Matches `DesktopSerial`'s, and that is load-bearing rather than tidy: a read
/// timeout is turned into a port DISCONNECT by `UsbSerialManager`, so a shorter
/// timeout here would fake an unplug on any slow lap and a longer one would make a
/// real unplug take longer to notice than it does in production.
const READ_TIMEOUT: Duration = Duration::from_millis(5_000);

/// The rig's pty slave paths, one per line, re-read on every enumeration.
pub struct PtySerial {
    manifest: PathBuf,
}

impl PtySerial {
    pub fn new(manifest: impl Into<PathBuf>) -> Self {
        Self {
            manifest: manifest.into(),
        }
    }
}

impl Serial for PtySerial {
    /// Read the manifest EVERY time, deliberately: dropping a line is an unplug and
    /// putting it back is a replug, with no app restart involved, which is how the
    /// rig drives `UsbSerialManager`'s disconnect path. A missing or unreadable
    /// manifest therefore means "every device unplugged", not an error.
    fn available_ports(&self) -> Vec<PortDesc> {
        let text = std::fs::read_to_string(&self.manifest).unwrap_or_default();
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|id| PortDesc {
                id: id.to_owned(),
                vid: USB_VID,
                pid: USB_PID,
            })
            .collect()
    }

    fn open_device_port(&self, id: &str, baud_rate: u32) -> Result<SerialPort, PortOpenError> {
        // NO FALLBACK: only this rig's own ptys, so a stale port name from a previous
        // run — or a real serial device — cannot be opened through the test transport.
        if !self.available_ports().iter().any(|port| port.id == id) {
            return Err(PortOpenError::Other(
                format!(
                    "{id} is not in the app rig manifest {}",
                    self.manifest.display()
                )
                .into(),
            ));
        }
        event!(
            Level::INFO,
            port = id,
            requested_baud = baud_rate,
            "opening rig pty (baud is ignored: a pty has no line rate)"
        );
        // BAUD 0, NOT `baud_rate`, and this is the trap that makes the whole
        // transport work. On macOS `serialport`'s open calls the IOSSIOSPEED ioctl
        // whenever the requested rate is non-zero, and that ioctl fails with ENOTTY
        // on a pseudo-terminal — the crate says so itself (posix/termios.rs, "attempting
        // to set the baud rate on a pseudo terminal via this ioctl call will fail with
        // the ENOTTY error"), and its own pty example passes 0. So `DesktopSerial`
        // CANNOT open a pty on this platform; passing the manager's 19,200 through
        // here would fail every open with a message about a tty. A pty has no line
        // rate to set, so nothing is being weakened: the framing above is unchanged.
        serialport::new(id, 0)
            .timeout(READ_TIMEOUT)
            .open()
            .map_err(|e| {
                let msg = e.to_string();
                if msg == "Device or resource busy" {
                    PortOpenError::DeviceBusy
                } else if msg == "Permission denied" {
                    PortOpenError::PermissionDenied
                } else {
                    PortOpenError::Other(Box::new(e))
                }
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use frostsnap_coordinator::serialport::{SerialPort as _, TTYPort};
    use frostsnap_coordinator::{DeviceChange, UsbSerialManager};
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::process::{Child, Command};
    use std::time::Instant;

    /// The two facts this transport stands on, both of which had to be MEASURED
    /// rather than assumed:
    ///
    ///  1. a pty slave can be opened BY PATH while another process still holds a
    ///     slave fd open (the rig holds one so the stub never sees a premature EOF), and
    ///  2. `bytes_to_read()` — FIONREAD, which is the whole of
    ///     `FramedSerialPort::anything_to_read()` — reports data on the SLAVE. On a
    ///     Darwin master it always returns 0, which is why the app is on the slave.
    #[test]
    fn opens_a_pty_slave_by_path_and_sees_bytes_on_it() {
        let (mut master, held_slave) = TTYPort::pair().expect("TTYPort::pair");
        let path = held_slave.name().expect("a pty slave has a path");

        let dir = std::env::temp_dir().join(format!("frostsnap-rig-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = dir.join("ports.txt");
        std::fs::write(&manifest, format!("# rig\n{path}\n")).unwrap();
        let serial = PtySerial::new(&manifest);

        let ports = serial.available_ports();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].id, path);
        // The manager's own filter drops anything else, so these must match.
        assert_eq!((ports[0].vid, ports[0].pid), (USB_VID, USB_PID));

        // Anything not in the manifest is unopenable through this transport.
        assert!(serial
            .open_device_port("/dev/tty.definitely-not-the-rig", 19_200)
            .is_err());

        let mut port = serial
            .open_device_port(&path, frostsnap_coordinator::frostsnap_comms::BAUDRATE)
            .expect("the rig's pty slave must open by path");
        master.write_all(b"hello").unwrap();
        master.flush().unwrap();

        let mut seen = 0;
        for _ in 0..100 {
            seen = port.bytes_to_read().expect("FIONREAD on the slave");
            if seen >= 5 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            seen, 5,
            "FIONREAD must report the master's bytes on the slave"
        );
        let mut buf = [0u8; 5];
        port.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");

        // THE BAUD TRAP, measured rather than quoted: the same open with the
        // manager's real rate fails, because IOSSIOSPEED is ENOTTY on a pty. If this
        // assertion ever fails, `serialport` fixed it and `open_device_port` may pass
        // `baud_rate` through again -- fix the comment there too.
        assert!(
            serialport::new(&path, 19_200)
                .timeout(READ_TIMEOUT)
                .open()
                .is_err(),
            "a non-zero baud rate is expected to fail on a pty (IOSSIOSPEED/ENOTTY)"
        );

        // An empty manifest is every device unplugged, not an error.
        std::fs::write(&manifest, "").unwrap();
        assert!(serial.available_ports().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// SIGTERM, not SIGKILL, on every exit path from the test below: the rig reaps its
    /// own stub children in a `finally`, and SIGKILL would skip it and leak them.
    struct Reaped(Child);

    impl Drop for Reaped {
        fn drop(&mut self) {
            let _ = Command::new("/bin/kill")
                .arg(self.0.id().to_string())
                .status();
            let _ = self.0.wait();
        }
    }

    /// THE TRANSPORT CARRYING A REAL HANDSHAKE, through the shipping
    /// `UsbSerialManager` — the port state machine `hostcheck` bypasses entirely.
    /// Each of two independent stub processes gets its own pty and must announce its
    /// own `DeviceId` to this coordinator.
    ///
    /// `#[ignore]`d because it spawns cold-snap's rig, so the default `cargo test` of
    /// this crate stays hermetic. It does NOT skip when the environment is missing —
    /// it fails — because a check that passes by not running is not a check:
    ///
    /// ```text
    /// COLDSNAP_REPO="$HOME/repos/cold-snap" \
    ///   cargo test -p rust_lib_frostsnapp --lib -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "spawns cold-snap/tools/app-rig.py; set COLDSNAP_REPO and build the stub first"]
    fn two_rig_devices_announce_to_a_real_usb_serial_manager() {
        let repo =
            std::env::var("COLDSNAP_REPO").expect("set COLDSNAP_REPO to the cold-snap checkout");
        let dir = std::env::temp_dir().join(format!("frostsnap-rig-e2e-{}", std::process::id()));
        let manifest = dir.join("ports.txt");
        let identities = dir.join("identities.tsv");
        // --timeout is a backstop: the rig tears itself down even if this process dies
        // without running `Reaped`'s drop.
        let rig = Reaped(
            Command::new("python3")
                .arg(format!("{repo}/tools/app-rig.py"))
                .args(["--devices", "2", "--timeout", "120", "--dir"])
                .arg(&dir)
                .spawn()
                .expect("spawn app-rig.py"),
        );

        // identities.tsv appears only after every child announced a DISTINCT DeviceId,
        // so waiting for it also waits out the rig's own duplicate-identity check.
        let deadline = Instant::now() + Duration::from_secs(60);
        while !identities.is_file() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let table = std::fs::read_to_string(&identities)
            .expect("the rig must publish identities.tsv; see its stderr above");
        let expected: Vec<String> = table
            .lines()
            .filter_map(|line| line.split_once('\t').map(|(_, id)| id.to_owned()))
            .collect();
        assert_eq!(expected.len(), 2, "two devices, one pty each");

        let mut manager = UsbSerialManager::new(Box::new(PtySerial::new(&manifest)));
        let mut announced: BTreeMap<String, String> = BTreeMap::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        while announced.len() < expected.len() && Instant::now() < deadline {
            for change in manager.poll_ports() {
                if let DeviceChange::Connected {
                    id,
                    firmware_digest,
                    ..
                } = change
                {
                    announced.insert(format!("{id:?}"), firmware_digest.to_string());
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        println!("announced: {announced:#?}");
        for id in &expected {
            assert!(
                announced.contains_key(id),
                "{id} (which the rig launched) never announced to the coordinator; got {:?}",
                announced.keys()
            );
        }
        drop(rig);
    }
}
