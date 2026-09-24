//! cold-snap's REAL upgrade listener in its own process, on a pty.
//!
//! `firmware/examples/stub` with `STUB_UPGRADE=1` runs `upgrade::run` over its
//! stdio (a `FakePsram` sized to the device's own `BURN_LEN_MAX`), and exits once
//! an image is staged. The stub is handed the pty MASTER; the coordinator side
//! opens the SLAVE by path, because FIONREAD on a Darwin master is always 0.
//!
//! Needs `COLDSNAP_REPO` and a built stub
//! (`cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub`
//! in cold-snap). Missing either is a FAILURE, never a skip.
#![allow(dead_code)]

use serialport::{SerialPort as _, TTYPort};
use std::os::fd::{AsFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub fn coldsnap() -> PathBuf {
    PathBuf::from(
        std::env::var("COLDSNAP_REPO").expect("set COLDSNAP_REPO to the cold-snap checkout"),
    )
}

pub fn fixture(rel: &str) -> PathBuf {
    let p = coldsnap().join("target/software-only").join(rel);
    assert!(p.is_file(), "missing fixture {}", p.display());
    p
}

/// A running stager. Dropping it SIGTERMs and reaps the child.
pub struct Stager {
    child: Option<Child>,
    /// Held so the stub never reads EOF before the coordinator opens the path.
    _held_slave: TTYPort,
    /// The slave's path: what the coordinator opens.
    pub path: String,
}

impl Stager {
    pub fn spawn() -> Self {
        let stub = coldsnap().join("target/aarch64-apple-darwin/debug/examples/stub");
        assert!(
            stub.is_file(),
            "no stub at {} -- build it first",
            stub.display()
        );
        let (master, held_slave) = TTYPort::pair().expect("TTYPort::pair");
        let path = held_slave.name().expect("a pty slave has a path");
        let wire_in = unsafe { OwnedFd::from_raw_fd(master.into_raw_fd()) };
        let wire_out = wire_in.as_fd().try_clone_to_owned().unwrap();
        let child = Command::new(&stub)
            .env("STUB_UPGRADE", "1")
            .stdin(Stdio::from(wire_in))
            .stdout(Stdio::from(wire_out))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn the stub");
        // The `Command` (and with it the parent's copies of the master) is gone
        // here, so the child holds the only master: when it exits, the slave sees
        // the wire close.
        Self {
            child: Some(child),
            _held_slave: held_slave,
            path,
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    /// Wait for the stub to exit ON ITS OWN (it does after `Outcome::Staged`).
    pub fn exited_within(&mut self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if let Some(_status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }
}

impl Drop for Stager {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return; // already exited and reaped
            }
            let _ = Command::new("/bin/kill")
                .arg(child.id().to_string())
                .status();
            let _ = child.wait();
        }
    }
}

/// Is `pid` still a process? `kill -0` succeeds only if it is.
pub fn alive(pid: u32) -> bool {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Can the path be opened again? A port left locked (TIOCEXCL) or held would not.
pub fn reopenable(path: &str) -> bool {
    serialport::new(path, 0)
        .timeout(Duration::from_millis(100))
        .open()
        .is_ok()
}
