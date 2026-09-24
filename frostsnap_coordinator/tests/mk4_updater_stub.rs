//! The shipped Mk4 updater — the `coldsnap-mk4-update` CLI and
//! `UsbSerialManager::run_mk4_upgrade` — against ptys.
//!
//! Two tiers:
//! * hermetic: the CLI refuses a bad artifact before it opens the port (zero
//!   bytes reach the pty), and refuses bad usage;
//! * `#[ignore]`d, needs `COLDSNAP_REPO` and a built stub: cold-snap's REAL
//!   upgrade listener in its own process stages the real task-01 artifacts and
//!   an unregistered local build, through the CLI and through the API, and every
//!   stub exits on its own (no orphan) and leaves its pty reopenable. FAILS,
//!   never skips, when the environment is missing:
//!
//! ```text
//! COLDSNAP_REPO="$HOME/repos/cold-snap" \
//!   cargo test --target aarch64-apple-darwin -p frostsnap_coordinator \
//!   --test mk4_updater_stub -- --ignored
//! ```
//!
//! WHAT THIS IS NOT: a device. The peer is `firmware/examples/stub` over a
//! `FakePsram`; "staged" is its digest verdict over that double. Nothing installs.

#[path = "support/mk4_key0.rs"]
mod mk4_key0;
#[path = "support/stub.rs"]
mod stub;

use frostsnap_coordinator::device_profile::registered_mk4_revision;
use frostsnap_coordinator::mk4_firmware::Mk4Firmware;
use frostsnap_coordinator::mk4_upgrade::{Mk4UpgradeError, Mk4UpgradeState};
use frostsnap_coordinator::{ExplicitPort, UsbSerialManager};
use serialport::{SerialPort as _, TTYPort};
use std::io::Read;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const CLI: &str = env!("CARGO_BIN_EXE_coldsnap-mk4-update");

fn cli(args: &[&str]) -> Output {
    Command::new(CLI).args(args).output().expect("run the CLI")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Nothing arrives on the master within `wait`. (FIONREAD is useless on a Darwin
/// master, so this is a timed read.)
fn master_silent(master: &mut TTYPort, wait: Duration) -> bool {
    master.set_timeout(wait).unwrap();
    let mut buf = [0u8; 64];
    match master.read(&mut buf) {
        Ok(0) => true,
        Ok(n) => panic!("{n} byte(s) reached the port: {:02x?}", &buf[..n]),
        Err(e) => e.kind() == std::io::ErrorKind::TimedOut,
    }
}

/// Artifact and bounds checks apply through the CLI too, and they run before
/// the port is opened: a refused image puts zero bytes on the wire.
#[test]
fn the_cli_refuses_bad_artifacts_before_touching_the_port() {
    let (mut master, slave) = TTYPort::pair().expect("pty");
    let path = slave.name().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let esp32 = dir.path().join("esp32.bin");
    std::fs::write(&esp32, include_bytes!("v0.0.1-firmware-signed.bin")).unwrap();
    let mut bad_sig = mk4_key0::ok_image();
    bad_sig[0x3f80 + 70] ^= 1;
    let bad_sig_path = dir.path().join("bad-sig.bin");
    std::fs::write(&bad_sig_path, &bad_sig).unwrap();
    let truncated = dir.path().join("truncated.bin");
    let whole = mk4_key0::ok_image();
    std::fs::write(&truncated, &whole[..200_000]).unwrap();
    // The refusal must name truncation against the header's own length.
    let truncated_why = format!("Truncated {{ header: {}, file: 200000 }}", whole.len());
    let not_dfu = dir.path().join("garbage.dfu");
    std::fs::write(&not_dfu, b"DfuSe\x01 not really").unwrap();

    for (file, needle) in [
        (&esp32, "ESP32"),
        (&bad_sig_path, "ignature"),
        (&truncated, truncated_why.as_str()),
        (&not_dfu, "Container(TooShort(17))"),
        (&dir.path().join("missing.bin"), "NotFound"),
    ] {
        let out = cli(&["--port", &path, file.to_str().unwrap()]);
        let said = text(&out);
        assert_eq!(out.status.code(), Some(2), "{}: {said}", file.display());
        assert!(said.contains("REFUSED"), "{said}");
        assert!(said.contains(needle), "expected {needle:?} in: {said}");
    }
    assert!(
        master_silent(&mut master, Duration::from_millis(300)),
        "a refused artifact reached the port"
    );

    // And usage errors never guess a port.
    for args in [&[][..], &["firmware.bin"][..], &["--port", &path][..]] {
        assert_eq!(cli(args).status.code(), Some(2));
    }
    assert!(master_silent(&mut master, Duration::from_millis(100)));
}

// ------------------------------------------------------------- real stager tier

/// Run the CLI against a fresh real stager and require it to stage.
fn cli_stages(rel: &str) -> Mk4Firmware {
    let fw = Mk4Firmware::load(stub::fixture(rel)).expect("the fixture loads");
    let mut stager = stub::Stager::spawn();
    let pid = stager.pid();
    let file = stub::fixture(rel);
    let out = cli(&["--port", &stager.path, file.to_str().unwrap()]);
    let said = text(&out);
    println!("{said}");
    assert_eq!(out.status.code(), Some(0), "{rel}: {said}");
    assert!(
        said.contains(&format!(
            "STAGED {} bytes, digest {}",
            fw.size(),
            fw.digest()
        )),
        "{said}"
    );
    assert!(said.contains("NOT installed"), "{said}");
    assert!(!said.to_lowercase().contains("installed successfully"));
    // `upgrade::run` returns on `Outcome::Staged` and the stub exits: THAT is the
    // device-side proof the final ack meant a matched digest, and it is also the
    // no-orphan check.
    assert!(
        stager.exited_within(Duration::from_secs(10)),
        "the stub did not finish after staging"
    );
    assert!(!stub::alive(pid));
    assert!(
        stub::reopenable(&stager.path),
        "the CLI left its pty locked or held"
    );
    fw
}

#[test]
#[ignore = "needs COLDSNAP_REPO, the task-01/06 fixtures and a built stub"]
fn the_cli_stages_the_real_task01_image_into_the_real_stager() {
    cli_stages("package/firmware-signed.bin");
}

#[test]
#[ignore = "needs COLDSNAP_REPO, the task-01/06 fixtures and a built stub"]
fn the_cli_stages_an_unregistered_local_build_from_its_dfu() {
    let fw = cli_stages("fixtures/06/local-build/coldsnap-6.0.1lb.dfu");
    assert_eq!(fw.version(), "6.0.1lb");
    assert_eq!(
        registered_mk4_revision(&fw.digest()),
        None,
        "this leg only means something for a digest no registry names"
    );
}

/// The library entry point the app calls, over `ExplicitPort` on a pty, with
/// the real task-01 DFU container.
#[test]
#[ignore = "needs COLDSNAP_REPO, the task-01 fixtures and a built stub"]
fn the_api_stages_the_real_task01_dfu_into_the_real_stager() {
    let fw = Mk4Firmware::load(stub::fixture("package/coldsnap-6.0.0cs.dfu")).unwrap();
    let mut stager = stub::Stager::spawn();
    let mut manager = UsbSerialManager::new(Box::new(ExplicitPort::new(stager.path.clone())));
    let deadline = Instant::now() + Duration::from_secs(30);
    while !manager.mk4_upgrade_ports().contains(&stager.path) {
        assert!(Instant::now() < deadline, "the stager never answered magic");
        manager.poll_ports();
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut states = vec![];
    let result = manager.run_mk4_upgrade(&stager.path, &fw, |s| states.push(s));
    assert_eq!(
        result,
        Ok(Mk4UpgradeState::Staged {
            size: fw.size(),
            digest: fw.digest()
        })
    );
    assert!(!result.unwrap().is_installed());
    assert_eq!(states.len(), fw.num_chunks() as usize);
    assert!(stager.exited_within(Duration::from_secs(10)));

    // The stub has gone: the port is dropped and cannot be selected again.
    assert!(matches!(
        manager.run_mk4_upgrade(&stager.path, &fw, |_| {}),
        Err(Mk4UpgradeError::PortNotReady { .. })
    ));
    drop(manager);
    assert!(stub::reopenable(&stager.path));
}
