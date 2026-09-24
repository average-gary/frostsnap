//! Port-scoped staging of a checked Mk4 image into cold-snap's upgrade listener,
//! and the one chunk/ack rule every firmware transfer in this crate uses.
//!
//! # The peer
//!
//! cold-snap's pre-`Session` listener (`firmware/src/upgrade.rs` `run`) is entered
//! by holding OK at power-up. It has no `DeviceId`, never `Announce`s and cannot
//! send `AckUpgradeMode`: its whole outbound vocabulary is `MAGIC_REPLY` and the
//! `0x11` ready byte. So this flow is keyed on a PORT, not a device, waits for no
//! confirmation ceremony, and learns a refusal only as an ack that never arrives.
//!
//! # The contract (task 05's, unchanged)
//!
//! 1. `PrepareUpgrade2 { size, two-range digest }` then `EnterUpgradeMode`, as
//!    framed messages, written in ONE write. The legacy `PrepareUpgrade` is never
//!    sent (the listener refuses it, `Refuse::Legacy`). Writing both frames
//!    together makes coalesced admission the normal case rather than a timing
//!    accident: the listener admits every frame of a packet in order.
//! 2. [`READINESS_GAP`], then [`FramedSerialPort::discard_input`]. The listener's
//!    framer buffers, so chunk bytes that arrive in the same read as
//!    `EnterUpgradeMode` would be lost into it; the gap is the only readiness
//!    mechanism the protocol documents (cold-snap DECISIONS.md §8(c)), and the
//!    digest is the backstop that turns any loss into a refusal. The discard
//!    clears handshake residue (a second `MAGIC_REPLY` starts `0x00` and would
//!    otherwise read as chunk 0's ack).
//! 3. Raw 4,096-byte chunks, the last one short if the image is. After EACH chunk
//!    exactly one byte is read and it must be `0x11` ([`send_chunk`]), and
//!    nothing may be waiting behind it; after the FINAL ack the port must also
//!    stay silent for [`FINAL_ACK_QUIET`] ([`ChunkError::SurplusAck`]).
//! 4. The final ack is the listener's digest verdict over its PSRAM read-back,
//!    and nothing more: [`Mk4UpgradeState::Staged`]. Nothing is burned.
//!
//! # What this is NOT
//!
//! Not an installer. No peer in this tree can install (callgate 18/7 is unbound),
//! so no path here produces [`Mk4UpgradeState::VerifiedReconnect`]; that needs the
//! task-07 installation controller and the new firmware announcing itself.

use crate::mk4_firmware::Mk4Firmware;
use crate::FramedSerialPort;
use frostsnap_comms::{
    CoordinatorSendBody, CoordinatorSendMessage, CoordinatorUpgradeMessage, Destination,
    ReceiveSerial, Sha256Digest, Upstream, BINCODE_CONFIG, FIRMWARE_NEXT_CHUNK_READY_SIGNAL,
    FIRMWARE_UPGRADE_CHUNK_LEN,
};
use frostsnap_core::DeviceId;
use std::io::ErrorKind;
use std::time::Duration;

/// The gap after the admission frames before the first raw byte. The same 100 ms
/// the native path has always left after `EnterUpgradeMode`.
pub const READINESS_GAP: Duration = Duration::from_millis(100);

/// How long the port must stay silent after the final ack before it counts as
/// the stage verdict. A surplus `0x11` earlier in the stream shifts every later
/// ack by one, so the "final" ack read would be the previous chunk's while the
/// real verdict is still on its way; this is where that late byte shows up.
// ponytail: a fixed window, so a verdict slower than this after a shifted ack
// still slips through; per-chunk surplus checks catch the usual same-write case.
pub const FINAL_ACK_QUIET: Duration = Duration::from_millis(100);

/// Why one chunk's write-then-ack failed. Every variant ends the transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkError {
    /// A byte arrived and it was not `0x11`.
    WrongAck { chunk: u32, of: u32, byte: u8 },
    /// Nothing arrived (or the write could not drain) within the port timeout.
    Timeout { chunk: u32, of: u32 },
    /// End of stream or any other I/O error: the peer is gone.
    Disconnected { chunk: u32, of: u32, error: String },
    /// The ack was `0x11` but more input was waiting behind it. An Mk4 listener
    /// sends exactly one byte per chunk, so any surplus would be read as a later
    /// chunk's ack and shift the final digest verdict by one.
    SurplusAck { chunk: u32, of: u32, pending: usize },
}

impl core::fmt::Display for ChunkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChunkError::WrongAck { chunk, of, byte } => write!(
                f,
                "chunk {chunk} of {of} was answered with {byte:#04x}, not the ready signal 0x11"
            ),
            ChunkError::Timeout { chunk, of } => {
                write!(
                    f,
                    "no acknowledgement for chunk {chunk} of {of} before the timeout"
                )
            }
            ChunkError::Disconnected { chunk, of, error } => {
                write!(f, "the port went away at chunk {chunk} of {of}: {error}")
            }
            ChunkError::SurplusAck { chunk, of, pending } => write!(
                f,
                "chunk {chunk} of {of} was acknowledged but {pending} more byte(s) followed; \
                 exactly one 0x11 per chunk is allowed"
            ),
        }
    }
}

impl std::error::Error for ChunkError {}

fn io_error(e: std::io::Error, chunk: u32, of: u32) -> ChunkError {
    match e.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => ChunkError::Timeout { chunk, of },
        _ => ChunkError::Disconnected {
            chunk,
            of,
            error: e.to_string(),
        },
    }
}

/// Write one chunk in full, then read EXACTLY one byte and require `0x11`.
///
/// THE shared chunk rule: the native ESP32 runner and the Mk4 updater both go
/// through here, so neither can log a wrong byte and carry on.
///
/// It does NOT require the port to be empty after the ack: the ESP32 device
/// sends its ready byte AHEAD of each chunk (`device/src/ota.rs`), so the next
/// one can legitimately be waiting. The Mk4 listener acks AFTER each chunk, so
/// [`stage_bytes`] adds that check ([`ChunkError::SurplusAck`]).
pub(crate) fn send_chunk<D: frostsnap_comms::Direction>(
    io: &mut FramedSerialPort<D>,
    chunk: u32,
    of: u32,
    bytes: &[u8],
) -> Result<(), ChunkError> {
    io.raw_write(bytes).map_err(|e| io_error(e, chunk, of))?;
    let mut byte = [0u8; 1];
    io.raw_read(&mut byte).map_err(|e| io_error(e, chunk, of))?;
    if byte[0] != FIRMWARE_NEXT_CHUNK_READY_SIGNAL {
        return Err(ChunkError::WrongAck {
            chunk,
            of,
            byte: byte[0],
        });
    }
    Ok(())
}

/// Where a Mk4 update stands. Distinct states, so nothing can read one as another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mk4UpgradeState {
    /// `chunks_acked` of `total_chunks` chunks written and acknowledged.
    Transferring {
        chunks_acked: u32,
        total_chunks: u32,
    },
    /// The final ack arrived: the peer read the image back and its digest matched.
    /// That is ALL it proves — nothing is installed.
    Staged { size: u32, digest: Sha256Digest },
    /// The peer accepted an install request for the staged image. No peer in this
    /// tree can (task 07 supplies the installation controller).
    InstallRequested { digest: Sha256Digest },
    /// After an install request, a device announced the staged image's digest as
    /// its running firmware. The only state that means "installed".
    VerifiedReconnect {
        device_id: DeviceId,
        digest: Sha256Digest,
    },
}

impl Mk4UpgradeState {
    /// Only [`Mk4UpgradeState::VerifiedReconnect`] is an installation.
    pub fn is_installed(&self) -> bool {
        matches!(self, Mk4UpgradeState::VerifiedReconnect { .. })
    }

    /// `Staged` -> `InstallRequested`, for the task-07 controller to call once
    /// its peer has accepted the request. Any other state is returned unchanged
    /// as the `Err`.
    pub fn install_requested(self) -> Result<Self, Self> {
        match self {
            Mk4UpgradeState::Staged { digest, .. } => {
                Ok(Mk4UpgradeState::InstallRequested { digest })
            }
            other => Err(other),
        }
    }

    /// `InstallRequested` -> `VerifiedReconnect`, only when the reconnecting
    /// device announces exactly the staged digest. A reconnect after a staging-only
    /// transfer (still `Staged`) is refused however its digest reads.
    pub fn reconnected(self, device_id: DeviceId, announced: Sha256Digest) -> Result<Self, Self> {
        match self {
            Mk4UpgradeState::InstallRequested { digest } if digest == announced => {
                Ok(Mk4UpgradeState::VerifiedReconnect { device_id, digest })
            }
            other => Err(other),
        }
    }
}

/// Why a Mk4 update did not reach `Staged`. Every variant is terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mk4UpgradeError {
    /// The port is not connected, or never answered the magic handshake.
    PortNotReady { port: String },
    /// A device on this port announced itself in an ordinary session. Only the
    /// upgrade listener takes an image, and the raw stream would reach every
    /// device on the port.
    NotAnUpgradeListener { port: String, announced: usize },
    /// The admission frames could not be encoded or written.
    Admission { error: String },
    /// No ack for chunk 0: the peer refused `PrepareUpgrade2` (size bounds or its
    /// PSRAM self-test), or it is not a cold-snap upgrade listener at all.
    NotAdmitted,
    /// No final ack: the peer's PSRAM read-back did not match the digest, so the
    /// image is NOT staged.
    StageNotConfirmed { size: u32 },
    /// Any other chunk failure.
    Chunk(ChunkError),
}

impl core::fmt::Display for Mk4UpgradeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Mk4UpgradeError::PortNotReady { port } => write!(
                f,
                "{port} is not a ready port (not connected, or it never answered the handshake)"
            ),
            Mk4UpgradeError::NotAnUpgradeListener { port, announced } => write!(
                f,
                "{port} carries {announced} device(s) in a normal session; power the Mk4 up \
                 holding OK so only its upgrade listener is on the port"
            ),
            Mk4UpgradeError::Admission { error } => {
                write!(f, "could not send the upgrade admission frames: {error}")
            }
            Mk4UpgradeError::NotAdmitted => write!(
                f,
                "the peer did not accept the upgrade: unsupported peer, not in its upgrade \
                 listener, or it refused the announced size"
            ),
            Mk4UpgradeError::StageNotConfirmed { size } => write!(
                f,
                "all {size} bytes were sent but the peer did not confirm the digest: NOT staged"
            ),
            Mk4UpgradeError::Chunk(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Mk4UpgradeError {}

/// Stage `firmware` into the listener on `io`. The checks already happened: a
/// [`Mk4Firmware`] cannot exist without passing them.
pub(crate) fn stage<D: frostsnap_comms::Direction>(
    io: &mut FramedSerialPort<D>,
    firmware: &Mk4Firmware,
    on_state: &mut dyn FnMut(Mk4UpgradeState),
) -> Result<Mk4UpgradeState, Mk4UpgradeError> {
    stage_bytes(io, firmware.as_bytes(), firmware.digest(), on_state)
}

/// The admission frames as one buffer.
pub(crate) fn admission_frames(size: u32, digest: Sha256Digest) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for body in [
        CoordinatorUpgradeMessage::PrepareUpgrade2 {
            size,
            firmware_digest: digest,
        },
        CoordinatorUpgradeMessage::EnterUpgradeMode,
    ] {
        // `All` because the listener has no `DeviceId` to address, and scoped
        // anyway: this is a raw write down the one selected port.
        bincode::encode_into_std_write(
            ReceiveSerial::<Upstream>::Message(CoordinatorSendMessage {
                target_destinations: Destination::All,
                message_body: CoordinatorSendBody::Upgrade(body).into(),
            }),
            &mut out,
            BINCODE_CONFIG,
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Unchecked bytes. Crate-private on purpose: every public entry point takes a
/// [`Mk4Firmware`], so no caller outside can skip the artifact checks. The
/// crate's own tests use it to send what no checked image could (a corrupted
/// body, the 262,656-byte short-tail image).
pub(crate) fn stage_bytes<D: frostsnap_comms::Direction>(
    io: &mut FramedSerialPort<D>,
    image: &[u8],
    digest: Sha256Digest,
    on_state: &mut dyn FnMut(Mk4UpgradeState),
) -> Result<Mk4UpgradeState, Mk4UpgradeError> {
    let size = u32::try_from(image.len()).map_err(|_| Mk4UpgradeError::Admission {
        error: "image longer than u32".into(),
    })?;
    let total = size.div_ceil(FIRMWARE_UPGRADE_CHUNK_LEN);
    let frames =
        admission_frames(size, digest).map_err(|error| Mk4UpgradeError::Admission { error })?;
    io.raw_write(&frames)
        .map_err(|e| Mk4UpgradeError::Admission {
            error: e.to_string(),
        })?;
    std::thread::sleep(READINESS_GAP);
    io.discard_input()
        .map_err(|e| Mk4UpgradeError::Chunk(io_error(e, 0, total)))?;

    for (i, chunk) in image
        .chunks(FIRMWARE_UPGRADE_CHUNK_LEN as usize)
        .enumerate()
    {
        let i = i as u32;
        let sent = send_chunk(io, i, total, chunk).and_then(|()| {
            if i + 1 == total {
                std::thread::sleep(FINAL_ACK_QUIET);
            }
            match io.pending_input().map_err(|e| io_error(e, i, total))? {
                0 => Ok(()),
                pending => Err(ChunkError::SurplusAck {
                    chunk: i,
                    of: total,
                    pending,
                }),
            }
        });
        match sent {
            Ok(()) => {}
            Err(ChunkError::Timeout { chunk: 0, .. }) => return Err(Mk4UpgradeError::NotAdmitted),
            Err(ChunkError::Timeout { chunk, .. }) if chunk + 1 == total => {
                return Err(Mk4UpgradeError::StageNotConfirmed { size })
            }
            Err(e) => return Err(Mk4UpgradeError::Chunk(e)),
        }
        on_state(Mk4UpgradeState::Transferring {
            chunks_acked: i + 1,
            total_chunks: total,
        });
    }
    Ok(Mk4UpgradeState::Staged { size, digest })
}

#[cfg(test)]
#[path = "../tests/support/stub.rs"]
mod real_stager;

/// Unchecked bytes into cold-snap's REAL listener (a separate process on a pty):
/// the cases no checked `Mk4Firmware` can express. `#[ignore]`d; needs
/// `COLDSNAP_REPO` and a built stub, and FAILS without them.
#[cfg(test)]
mod tests {
    use super::real_stager::{alive, reopenable, Stager};
    use super::*;
    use crate::mk4_firmware::two_range_digest;
    use frostsnap_comms::Downstream;
    use std::time::Instant;

    /// Open the slave and complete the magic handshake, as the manager would.
    fn handshake(stager: &Stager) -> FramedSerialPort<Downstream> {
        let port = serialport::new(&stager.path, 0)
            .timeout(Duration::from_secs(3))
            .open()
            .expect("open the pty slave");
        let mut io = FramedSerialPort::<Downstream>::new(port);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(Instant::now() < deadline, "the stager never answered magic");
            io.write_magic_bytes().unwrap();
            std::thread::sleep(Duration::from_millis(50));
            if io.read_for_magic_bytes().unwrap().is_some() {
                return io;
            }
        }
    }

    /// A deterministic body whose header length field (offset 16,280, the
    /// listener's `LengthDisagreement` check) agrees with its own length. No
    /// signature: staging checks size, header length and digest, never authority.
    fn pattern(len: usize) -> Vec<u8> {
        let mut v: Vec<u8> = (0..len).map(|i| (i * 13 + i / 509) as u8).collect();
        v[16_280..16_284].copy_from_slice(&(len as u32).to_le_bytes());
        v
    }

    fn run(
        image: &[u8],
        digest: Sha256Digest,
    ) -> (
        Result<Mk4UpgradeState, Mk4UpgradeError>,
        Vec<Mk4UpgradeState>,
        Stager,
    ) {
        let stager = Stager::spawn();
        let mut io = handshake(&stager);
        let mut states = vec![];
        let result = stage_bytes(&mut io, image, digest, &mut |s| states.push(s));
        (result, states, stager)
    }

    /// 64 full chunks and a 512-byte tail: the short final chunk and its ack.
    #[test]
    #[ignore = "needs COLDSNAP_REPO and a built stub"]
    fn a_short_final_chunk_stages() {
        let image = pattern(256 * 1024 + 512);
        let digest = two_range_digest(&image);
        let (result, states, mut stager) = run(&image, digest);
        assert_eq!(
            result,
            Ok(Mk4UpgradeState::Staged {
                size: image.len() as u32,
                digest
            })
        );
        assert_eq!(states.len(), 65);
        assert_eq!(
            states.last(),
            Some(&Mk4UpgradeState::Transferring {
                chunks_acked: 65,
                total_chunks: 65
            })
        );
        let pid = stager.pid();
        assert!(
            stager.exited_within(Duration::from_secs(10)),
            "stub did not finish"
        );
        assert!(!alive(pid));
        assert!(reopenable(&stager.path));
    }

    /// One flipped body byte after the digest was taken: every chunk is acked
    /// except the last, whose ack is the digest verdict. Never `Staged`.
    #[test]
    #[ignore = "needs COLDSNAP_REPO and a built stub"]
    fn a_corrupted_body_is_never_staged() {
        let mut image = pattern(256 * 1024 + 512);
        let digest = two_range_digest(&image);
        image[40 * 4096 + 17] ^= 0x01;
        let (result, states, stager) = run(&image, digest);
        assert_eq!(
            result,
            Err(Mk4UpgradeError::StageNotConfirmed {
                size: image.len() as u32
            })
        );
        assert_eq!(states.len(), 64, "every chunk but the verdict was acked");
        assert!(states
            .iter()
            .all(|s| !matches!(s, Mk4UpgradeState::Staged { .. })));
        let pid = stager.pid();
        drop(stager);
        assert!(!alive(pid));
    }

    /// Below the listener's 256 KiB floor: refused at admission, so no ack at all.
    #[test]
    #[ignore = "needs COLDSNAP_REPO and a built stub"]
    fn an_undersized_image_is_not_admitted() {
        let image = pattern(128 * 1024);
        let (result, states, stager) = run(&image, two_range_digest(&image));
        assert_eq!(result, Err(Mk4UpgradeError::NotAdmitted));
        assert!(states.is_empty());
        let pid = stager.pid();
        drop(stager);
        assert!(!alive(pid));
    }
}
