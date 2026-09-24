//! Stage a checked cold-snap Mk4 image into the upgrade listener on ONE named port.
//!
//! ```text
//! coldsnap-mk4-update --port <path> <firmware-signed.bin | image.dfu>
//! ```
//!
//! Exit codes: 0 staged, 1 transfer failed, 2 usage or artifact refused (no port is
//! opened), 3 the port never came up as an upgrade listener.
//!
//! The port is never discovered: `ExplicitPort` exposes only the path given. The
//! artifact checks are format and transfer integrity under the published dev key
//! 0, not authenticity. "Staged" means the device's PSRAM read-back matched the
//! digest; nothing is installed.

use frostsnap_coordinator::mk4_firmware::Mk4Firmware;
use frostsnap_coordinator::mk4_upgrade::Mk4UpgradeState;
use frostsnap_coordinator::{ExplicitPort, UsbSerialManager};
use std::process::ExitCode;
use std::time::{Duration, Instant};

/// How long the port gets to answer the handshake.
const READY_DEADLINE: Duration = Duration::from_secs(30);
/// After the handshake, how long to keep polling for an `Announce` before
/// trusting that the peer is the listener (which never announces).
const ANNOUNCE_SETTLE: Duration = Duration::from_secs(1);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (port, image) = match args.as_slice() {
        [flag, port, image] if flag == "--port" => (port.clone(), image.clone()),
        _ => {
            eprintln!("usage: coldsnap-mk4-update --port <path> <firmware-signed.bin | image.dfu>");
            return ExitCode::from(2);
        }
    };

    // Every artifact check runs BEFORE the port is opened.
    let firmware = match Mk4Firmware::load(&image) {
        Ok(firmware) => firmware,
        Err(e) => {
            eprintln!("REFUSED {image}: {e} [{e:?}]");
            return ExitCode::from(2);
        }
    };
    println!(
        "checked {image}: {:?}, version {}, {} bytes, {} chunks, digest {} \
         (format/integrity under dev key 0, not authenticity)",
        firmware.container(),
        firmware.version(),
        firmware.size(),
        firmware.num_chunks(),
        firmware.digest()
    );

    let mut manager = UsbSerialManager::new(Box::new(ExplicitPort::new(port.clone())));
    let started = Instant::now();
    let mut ready_at = None;
    loop {
        manager.poll_ports();
        let listener = manager.mk4_upgrade_ports().contains(&port);
        let announced = manager
            .devices_by_ports()
            .get(&port)
            .is_some_and(|on| !on.is_empty());
        if announced {
            break; // `run_mk4_upgrade` refuses it by name
        }
        match (listener, ready_at) {
            (true, None) => ready_at = Some(Instant::now()),
            (true, Some(at)) if at.elapsed() >= ANNOUNCE_SETTLE => break,
            (true, Some(_)) => {}
            // Dropped again (the manager re-handshakes a port that misbehaves):
            // the settle starts over.
            (false, _) => ready_at = None,
        }
        if ready_at.is_none() && started.elapsed() > READY_DEADLINE {
            eprintln!(
                "FAILED: {port} never answered the handshake in {READY_DEADLINE:?} \
                 (is the Mk4 powered up holding OK?)"
            );
            return ExitCode::from(3);
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let result = manager.run_mk4_upgrade(&port, &firmware, |state| {
        if let Mk4UpgradeState::Transferring {
            chunks_acked,
            total_chunks,
        } = state
        {
            if chunks_acked % 16 == 0 || chunks_acked == total_chunks {
                eprintln!("chunk {chunks_acked}/{total_chunks} acknowledged");
            }
        }
    });
    match result {
        Ok(Mk4UpgradeState::Staged { size, digest }) => {
            println!("STAGED {size} bytes, digest {digest} on {port}: staged only, NOT installed");
            ExitCode::SUCCESS
        }
        Ok(other) => {
            // `run_mk4_upgrade` only ever returns `Staged`; anything else is a bug
            // and must not read as success.
            eprintln!("FAILED: unexpected final state {other:?}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("FAILED: {e} [{e:?}]");
            ExitCode::from(1)
        }
    }
}
