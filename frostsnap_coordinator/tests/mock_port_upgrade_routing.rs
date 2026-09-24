//! Mock-port proof that ESP32 upgrade traffic reaches only the selected ports.
//!
//! This drives the real [`UsbSerialManager`] over a fake [`Serial`] whose ports are
//! in-memory byte queues — no pty, no thread, no timeout, so a routing regression
//! is a failed assertion rather than a hung test. The device end of each port is a
//! real `FramedSerialPort<Upstream>`, so the magic-byte handshake and the
//! `Announce` framing are the shipped encoders and not a second implementation of
//! the wire format.
//!
//! WHAT THIS IS NOT. Unit-level: no device, no port, no USB. It proves the
//! coordinator's routing arithmetic, not that any hardware behaves as assumed.

use frostsnap_comms::{
    DeviceSendBody, DeviceSendMessage, Downstream, ReceiveSerial, Sha256Digest, Upstream,
};
use frostsnap_coordinator::{
    FirmwareBin, FramedSerialPort, PortDesc, PortOpenError, Serial, UsbSerialManager,
    ValidatedFirmwareBin,
};
use frostsnap_core::DeviceId;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// From `usb_serial_manager.rs` — a port is ignored unless it matches.
const USB_VID: u16 = 12346;
const USB_PID: u16 = 4097;

/// One direction of one port.
type Pipe = Arc<Mutex<Vec<u8>>>;

/// What a scripted peer does with one coordinator write.
enum Reply {
    Bytes(Vec<u8>),
    /// The peer is gone: every read after this is end-of-stream.
    HangUp,
}

/// A peer that answers each coordinator WRITE as it happens. Pre-seeded replies
/// cannot model the Mk4 updater: it discards stale input at the framed-to-raw
/// switch, which is exactly what it should do to a pre-seeded ack.
type Responder = Arc<Mutex<dyn FnMut(&[u8]) -> Reply + Send>>;

/// A port end: reads from `rx`, writes to `tx`.
struct FakePortEnd {
    name: String,
    rx: Pipe,
    tx: Pipe,
    responder: Option<Responder>,
    hung_up: Arc<AtomicBool>,
}

impl Read for FakePortEnd {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut rx = self.rx.lock().unwrap();
        let n = buf.len().min(rx.len());
        if n == 0 && self.hung_up.load(Ordering::SeqCst) {
            return Ok(0);
        }
        if n == 0 {
            // Never block: a test that would have waited forever fails instead.
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("nothing to read on {}", self.name),
            ));
        }
        buf[..n].copy_from_slice(&rx[..n]);
        rx.drain(..n);
        Ok(n)
    }
}

impl Write for FakePortEnd {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx.lock().unwrap().extend_from_slice(buf);
        if let Some(responder) = &self.responder {
            match (responder.lock().unwrap())(buf) {
                Reply::Bytes(bytes) => self.rx.lock().unwrap().extend(bytes),
                Reply::HangUp => self.hung_up.store(true, Ordering::SeqCst),
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl serialport::SerialPort for FakePortEnd {
    fn name(&self) -> Option<String> {
        Some(self.name.clone())
    }
    fn bytes_to_read(&self) -> serialport::Result<u32> {
        Ok(self.rx.lock().unwrap().len() as u32)
    }
    fn bytes_to_write(&self) -> serialport::Result<u32> {
        Ok(0)
    }
    fn baud_rate(&self) -> serialport::Result<u32> {
        Ok(frostsnap_comms::BAUDRATE)
    }
    fn data_bits(&self) -> serialport::Result<serialport::DataBits> {
        Ok(serialport::DataBits::Eight)
    }
    fn flow_control(&self) -> serialport::Result<serialport::FlowControl> {
        Ok(serialport::FlowControl::None)
    }
    fn parity(&self) -> serialport::Result<serialport::Parity> {
        Ok(serialport::Parity::None)
    }
    fn stop_bits(&self) -> serialport::Result<serialport::StopBits> {
        Ok(serialport::StopBits::One)
    }
    fn timeout(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
    fn set_baud_rate(&mut self, _: u32) -> serialport::Result<()> {
        Ok(())
    }
    fn set_data_bits(&mut self, _: serialport::DataBits) -> serialport::Result<()> {
        Ok(())
    }
    fn set_flow_control(&mut self, _: serialport::FlowControl) -> serialport::Result<()> {
        Ok(())
    }
    fn set_parity(&mut self, _: serialport::Parity) -> serialport::Result<()> {
        Ok(())
    }
    fn set_stop_bits(&mut self, _: serialport::StopBits) -> serialport::Result<()> {
        Ok(())
    }
    fn set_timeout(&mut self, _: std::time::Duration) -> serialport::Result<()> {
        Ok(())
    }
    fn write_request_to_send(&mut self, _: bool) -> serialport::Result<()> {
        Ok(())
    }
    fn write_data_terminal_ready(&mut self, _: bool) -> serialport::Result<()> {
        Ok(())
    }
    fn read_clear_to_send(&mut self) -> serialport::Result<bool> {
        Ok(true)
    }
    fn read_data_set_ready(&mut self) -> serialport::Result<bool> {
        Ok(true)
    }
    fn read_ring_indicator(&mut self) -> serialport::Result<bool> {
        Ok(false)
    }
    fn read_carrier_detect(&mut self) -> serialport::Result<bool> {
        Ok(true)
    }
    fn clear(&self, _: serialport::ClearBuffer) -> serialport::Result<()> {
        Ok(())
    }
    fn try_clone(&self) -> serialport::Result<Box<dyn serialport::SerialPort>> {
        Ok(Box::new(FakePortEnd {
            name: self.name.clone(),
            rx: self.rx.clone(),
            tx: self.tx.clone(),
            responder: self.responder.clone(),
            hung_up: self.hung_up.clone(),
        }))
    }
    fn set_break(&self) -> serialport::Result<()> {
        Ok(())
    }
    fn clear_break(&self) -> serialport::Result<()> {
        Ok(())
    }
}

/// A port as the test sees it: the two queues, plus the device end of the wire.
struct MockPort {
    /// Bytes the coordinator has written. This is the whole claim: for an
    /// unselected port it must stay empty.
    from_coordinator: Pipe,
    to_coordinator: Pipe,
}

/// The coordinator's end of one registered port.
struct PortSlot {
    name: String,
    rx: Pipe,
    tx: Pipe,
    responder: Option<Responder>,
    hung_up: Arc<AtomicBool>,
}

#[derive(Default, Clone)]
struct FakeSerial {
    ports: Arc<Mutex<Vec<PortSlot>>>,
}

impl FakeSerial {
    /// Register a port and hand back the device end of it.
    fn add_port(&self, name: &str) -> (MockPort, FramedSerialPort<Upstream>) {
        self.add_port_with(name, None)
    }

    /// As [`FakeSerial::add_port`], with a peer that answers every coordinator write.
    fn add_port_with(
        &self,
        name: &str,
        responder: Option<Responder>,
    ) -> (MockPort, FramedSerialPort<Upstream>) {
        let from_coordinator: Pipe = Default::default();
        let to_coordinator: Pipe = Default::default();
        self.ports.lock().unwrap().push(PortSlot {
            name: name.to_string(),
            rx: to_coordinator.clone(),
            tx: from_coordinator.clone(),
            responder,
            hung_up: Default::default(),
        });
        let device_end = FakePortEnd {
            name: format!("{name}:device"),
            rx: from_coordinator.clone(),
            tx: to_coordinator.clone(),
            responder: None,
            hung_up: Default::default(),
        };
        (
            MockPort {
                from_coordinator,
                to_coordinator,
            },
            FramedSerialPort::new(Box::new(device_end)),
        )
    }
}

impl Serial for FakeSerial {
    fn available_ports(&self) -> Vec<PortDesc> {
        self.ports
            .lock()
            .unwrap()
            .iter()
            .map(|slot| PortDesc {
                id: slot.name.clone(),
                vid: USB_VID,
                pid: USB_PID,
            })
            .collect()
    }

    fn open_device_port(
        &self,
        unique_id: &str,
        _baud_rate: u32,
    ) -> Result<Box<dyn serialport::SerialPort>, PortOpenError> {
        let ports = self.ports.lock().unwrap();
        let slot = ports
            .iter()
            .find(|slot| slot.name == unique_id)
            .expect("port exists");
        Ok(Box::new(FakePortEnd {
            name: slot.name.clone(),
            rx: slot.rx.clone(),
            tx: slot.tx.clone(),
            responder: slot.responder.clone(),
            hung_up: slot.hung_up.clone(),
        }))
    }
}

fn bundle() -> ValidatedFirmwareBin {
    FirmwareBin::new(include_bytes!("v0.0.1-firmware-signed.bin"))
        .validate()
        .expect("fixture is a valid firmware image")
}

/// The first registered cold-snap Mk4 revision, read from the registry itself.
fn mk4_digest() -> Sha256Digest {
    include_str!("../src/coldsnap-mk4-registry.txt")
        .lines()
        .find(|line| !line.starts_with('#') && line.contains(' '))
        .and_then(|line| line.split_once(' '))
        .expect("the registry has at least one entry")
        .0
        .parse()
        .expect("registry holds a sha256")
}

/// Bring a device up on its port: magic bytes, then `Announce`.
fn announce(device_end: &mut FramedSerialPort<Upstream>, id: DeviceId, digest: Sha256Digest) {
    device_end.write_magic_bytes().expect("magic bytes");
    device_end.queue_send(
        DeviceSendMessage {
            from: id,
            body: DeviceSendBody::Announce {
                firmware_digest: digest,
            },
        }
        .into(),
    );
    device_end.poll_send().expect("announce");
}

fn device(n: u8) -> DeviceId {
    DeviceId([n; 33])
}

struct Fixture {
    manager: UsbSerialManager,
    esp32_port: MockPort,
    mk4_port: MockPort,
    /// An ESP32 with a cold-snap Mk4 daisy-chained behind it on one port.
    mixed_port: MockPort,
}

const ESP32: DeviceId = DeviceId([1; 33]);
const MK4: DeviceId = DeviceId([2; 33]);
const MIXED_ESP32: DeviceId = DeviceId([3; 33]);
const MIXED_MK4: DeviceId = DeviceId([4; 33]);

/// Three ports up and announced, with the coordinator's own handshake writes
/// cleared so every later byte on a port came from the upgrade.
fn fixture() -> Fixture {
    let serial = FakeSerial::default();
    let (esp32_port, mut esp32_end) = serial.add_port("port-esp32");
    let (mk4_port, mut mk4_end) = serial.add_port("port-mk4");
    let (mixed_port, mut mixed_end) = serial.add_port("port-mixed");

    announce(&mut esp32_end, ESP32, bundle().digest());
    announce(&mut mk4_end, MK4, mk4_digest());
    // One port, two devices: `Announce` from both, as a daisy chain looks.
    announce(&mut mixed_end, MIXED_ESP32, bundle().digest());
    mixed_end.queue_send(
        DeviceSendMessage {
            from: MIXED_MK4,
            body: DeviceSendBody::Announce {
                firmware_digest: mk4_digest(),
            },
        }
        .into(),
    );
    mixed_end.poll_send().expect("second announce");

    let mut manager = UsbSerialManager::new(Box::new(serial)).with_firmware_bin(bundle());
    // open ports, read magic bytes, read announcements, flush the acks
    for _ in 0..4 {
        manager.poll_ports();
    }

    let by_port = manager.devices_by_ports();
    assert_eq!(
        by_port.get("port-esp32").map(Vec::as_slice),
        Some(&[ESP32][..])
    );
    assert_eq!(by_port.get("port-mk4").map(Vec::as_slice), Some(&[MK4][..]));
    assert_eq!(
        by_port.get("port-mixed").map(Vec::as_slice),
        Some(&[MIXED_ESP32, MIXED_MK4][..]),
        "the mixed port must carry both devices for this test to mean anything"
    );

    for port in [&esp32_port, &mk4_port, &mixed_port] {
        port.from_coordinator.lock().unwrap().clear();
    }
    Fixture {
        manager,
        esp32_port,
        mk4_port,
        mixed_port,
    }
}

/// The device's side of the chunk protocol: one ready-signal byte per chunk. Seeded
/// up front so the test never waits on anything.
fn seed_chunk_acks(port: &MockPort, chunks: u32) {
    port.to_coordinator
        .lock()
        .unwrap()
        .extend(std::iter::repeat_n(
            frostsnap_comms::FIRMWARE_NEXT_CHUNK_READY_SIGNAL,
            chunks as usize + 8,
        ));
}

fn written(port: &MockPort) -> usize {
    port.from_coordinator.lock().unwrap().len()
}

/// CRITERION 3. The image goes down the selected port and the Mk4's port sees not
/// one byte — not the `EnterUpgradeMode` message, not a chunk.
#[test]
fn an_esp32_upgrade_never_reaches_an_mk4_port() {
    let mut f = fixture();
    let bin = bundle();
    seed_chunk_acks(&f.esp32_port, bin.num_chunks());

    let progress: Vec<_> = f
        .manager
        .run_firmware_upgrade(&BTreeSet::from([ESP32]))
        .expect("the ESP32 is selected, so there is somewhere to send")
        .collect();

    assert_eq!(
        progress.len(),
        bin.num_chunks() as usize,
        "every chunk should have been written"
    );
    assert!(
        progress.iter().all(Result::is_ok),
        "chunk writes failed: {progress:?}"
    );
    assert!(
        written(&f.esp32_port) > bin.size() as usize,
        "the selected port got the whole image plus the EnterUpgradeMode message"
    );
    assert_eq!(
        written(&f.mk4_port),
        0,
        "the Mk4's port received bytes during an ESP32 upgrade"
    );
    assert_eq!(
        written(&f.mixed_port),
        0,
        "a port with an unselected device on it received bytes"
    );
}

/// The Mk4's own port is refused even when the Mk4 is what was asked for: its
/// firmware refuses every `CoordinatorUpgradeMessage`, so the app has no update for
/// it and must not stream one anyway. Refused inside the manager, which is the last
/// gate before the raw bytes.
#[test]
fn streaming_to_an_mk4_is_refused_by_the_manager() {
    let mut f = fixture();

    let err = f
        .manager
        .run_firmware_upgrade(&BTreeSet::from([MK4]))
        .map(|_| ())
        .expect_err("an Mk4 must not be streamed an ESP32 image");
    assert!(
        err.to_string().contains("mk4"),
        "the refusal should name the firmware: {err}"
    );
    assert_eq!(written(&f.mk4_port), 0);

    // And it refuses the whole run rather than quietly dropping the Mk4 from it.
    let err = f
        .manager
        .run_firmware_upgrade(&BTreeSet::from([ESP32, MK4]))
        .map(|_| ())
        .expect_err("a set containing an Mk4 must be refused");
    assert!(err.to_string().contains("mk4"), "{err}");
    assert_eq!(written(&f.esp32_port), 0);
    assert_eq!(written(&f.mk4_port), 0);
}

/// MIXED CHAIN. The raw chunk stream has no addressing, so every device on a port
/// sees it: selecting only the ESP32 in front of a chained Mk4 cannot be honoured,
/// and is refused rather than leaked.
#[test]
fn a_chain_carrying_an_unselected_device_is_not_streamed_to() {
    let mut f = fixture();

    let err = f
        .manager
        .run_firmware_upgrade(&BTreeSet::from([MIXED_ESP32]))
        .map(|_| ())
        .expect_err("the chain also carries an Mk4, so there is nowhere to send");
    assert!(err.to_string().contains("nowhere to send"), "{err}");
    assert_eq!(written(&f.mixed_port), 0);
    assert_eq!(written(&f.mk4_port), 0);
    assert_eq!(written(&f.esp32_port), 0);
}

/// NATIVE BEHAVIOUR RETAINED. Two selected ESP32s on separate ports still both get
/// the image, and the progress denominator follows the ports actually written.
#[test]
fn every_selected_esp32_port_is_still_streamed_to() {
    let serial = FakeSerial::default();
    let (port_a, mut end_a) = serial.add_port("port-a");
    let (port_b, mut end_b) = serial.add_port("port-b");
    announce(&mut end_a, device(1), bundle().digest());
    announce(&mut end_b, device(2), bundle().digest());

    let mut manager = UsbSerialManager::new(Box::new(serial)).with_firmware_bin(bundle());
    for _ in 0..4 {
        manager.poll_ports();
    }
    for port in [&port_a, &port_b] {
        port.from_coordinator.lock().unwrap().clear();
        seed_chunk_acks(port, bundle().num_chunks());
    }

    let progress: Vec<_> = manager
        .run_firmware_upgrade(&BTreeSet::from([device(1), device(2)]))
        .expect("both are selected")
        .collect::<Result<Vec<_>, _>>()
        .expect("all chunks written");

    assert_eq!(progress.len(), 2 * bundle().num_chunks() as usize);
    assert!(written(&port_a) > bundle().size() as usize);
    assert!(written(&port_b) > bundle().size() as usize);
    let last = progress.last().copied().unwrap();
    assert!(
        (last - 1.0).abs() < f32::EPSILON,
        "progress should finish at 1.0, got {last}"
    );
}

/// Selecting nothing is an error, not a broadcast to every ready port — which is
/// what a no-argument `run_firmware_upgrade` used to be.
#[test]
fn an_empty_selection_sends_nothing() {
    let mut f = fixture();
    let err = f
        .manager
        .run_firmware_upgrade(&BTreeSet::new())
        .map(|_| ())
        .expect_err("no device selected");
    assert!(err.to_string().contains("nowhere to send"), "{err}");
    assert_eq!(written(&f.esp32_port), 0);
    assert_eq!(written(&f.mk4_port), 0);
    assert_eq!(written(&f.mixed_port), 0);
}

/// The fake is only worth anything if the coordinator really talked to it, so pin
/// that it did: a `Downstream` frame arrived from the coordinator after the
/// announce (the `AnnounceAck`).
#[test]
fn the_mock_ports_really_carry_the_wire_protocol() {
    let serial = FakeSerial::default();
    let (port, mut end) = serial.add_port("port-a");
    announce(&mut end, device(1), bundle().digest());

    let mut manager = UsbSerialManager::new(Box::new(serial)).with_firmware_bin(bundle());
    let mut connected = false;
    for _ in 0..4 {
        for change in manager.poll_ports() {
            connected |= matches!(
                change,
                frostsnap_coordinator::DeviceChange::Connected { id, .. } if id == device(1)
            );
        }
    }
    assert!(connected, "the manager never saw the announced device");
    assert!(
        written(&port) > 0,
        "the coordinator never wrote to the mock port"
    );

    // And what it wrote decodes as a real frame this device could act on.
    let frame: ReceiveSerial<Upstream> = bincode::decode_from_std_read(
        &mut std::io::Cursor::new(port.from_coordinator.lock().unwrap().clone()),
        frostsnap_comms::BINCODE_CONFIG,
    )
    .expect("the coordinator wrote a decodable frame");
    assert!(matches!(
        frame,
        ReceiveSerial::Message(_) | ReceiveSerial::MagicBytes(_)
    ));
    // Silence the unused-import warning for the direction the coordinator reads.
    let _: Option<ReceiveSerial<Downstream>> = None;
}

// ------------------------------------------------------------ the shared chunk rule

/// The native runner used to log a wrong ready byte at DEBUG and carry on. Now
/// it is a named failure, and nothing after it is written.
#[test]
fn a_wrong_ack_ends_a_native_upgrade() {
    let mut f = fixture();
    f.esp32_port
        .to_coordinator
        .lock()
        .unwrap()
        .extend([0x11, 0x5a, 0x11, 0x11, 0x11]);

    let progress: Vec<_> = f
        .manager
        .run_firmware_upgrade(&BTreeSet::from([ESP32]))
        .expect("the ESP32 is selected")
        .collect();

    assert_eq!(
        progress.len(),
        2,
        "one good chunk, then the failure, then nothing"
    );
    assert!(progress[0].is_ok());
    let err = progress[1]
        .as_ref()
        .expect_err("0x5a is not the ready signal");
    assert!(err.to_string().contains("0x5a"), "{err}");
    let w = written(&f.esp32_port);
    assert!(
        (2 * 4096..3 * 4096).contains(&w),
        "exactly two chunks (plus one small frame) should have been written, got {w} bytes"
    );
}

/// A missing ack is a named failure too, not a hang and not a success.
#[test]
fn a_missing_ack_ends_a_native_upgrade() {
    let mut f = fixture();
    f.esp32_port
        .to_coordinator
        .lock()
        .unwrap()
        .extend([0x11; 3]);

    let progress: Vec<_> = f
        .manager
        .run_firmware_upgrade(&BTreeSet::from([ESP32]))
        .expect("the ESP32 is selected")
        .collect();

    assert_eq!(progress.len(), 4);
    assert!(progress[..3].iter().all(Result::is_ok));
    let err = progress[3].as_ref().expect_err("no fourth ack was seeded");
    assert!(
        err.to_string().contains("no acknowledgement for chunk 3"),
        "{err}"
    );
    assert!((4 * 4096..5 * 4096).contains(&written(&f.esp32_port)));
}

// ------------------------------------------------------------- the Mk4 updater

#[path = "support/mk4_key0.rs"]
mod mk4_key0;

use frostsnap_comms::{CoordinatorSendBody, CoordinatorUpgradeMessage};
use frostsnap_coordinator::mk4_firmware::Mk4Firmware;
use frostsnap_coordinator::mk4_upgrade::{ChunkError, Mk4UpgradeError, Mk4UpgradeState};

fn mk4_image() -> Mk4Firmware {
    Mk4Firmware::from_artifact(&mk4_key0::ok_image()).expect("a key-0 image")
}

/// A scripted cold-snap upgrade listener: silent until `armed`, then the first
/// write is the admission frames and write `k + 1` is chunk `k`, answered by
/// `script(k)`. Records the length of every chunk write.
struct Listener {
    armed: Arc<AtomicBool>,
    chunk_writes: Arc<Mutex<Vec<usize>>>,
}

fn listener(
    serial: &FakeSerial,
    name: &str,
    script: impl Fn(u32) -> Reply + Send + 'static,
) -> (MockPort, Listener) {
    let armed = Arc::new(AtomicBool::new(false));
    let chunk_writes: Arc<Mutex<Vec<usize>>> = Default::default();
    let (a, c) = (armed.clone(), chunk_writes.clone());
    let mut admitted = false;
    let responder: Responder = Arc::new(Mutex::new(move |bytes: &[u8]| {
        if !a.load(Ordering::SeqCst) {
            return Reply::Bytes(vec![]);
        }
        if !admitted {
            admitted = true;
            return Reply::Bytes(vec![]);
        }
        let mut writes = c.lock().unwrap();
        writes.push(bytes.len());
        script(writes.len() as u32 - 1)
    }));
    let (port, mut end) = serial.add_port_with(name, Some(responder));
    // The listener answers the handshake and never announces. (Once: a second
    // decoded magic frame on a ready port is "Unexpected magic bytes" and the
    // manager drops the port. The raw residue case is injected by `mk4_fixture`.)
    end.write_magic_bytes().expect("magic");
    (
        port,
        Listener {
            armed,
            chunk_writes,
        },
    )
}

fn ack(_: u32) -> Reply {
    Reply::Bytes(vec![0x11])
}

struct Mk4Fixture {
    manager: UsbSerialManager,
    ports: Vec<(&'static str, MockPort)>,
    listener_a: Listener,
}

/// An ESP32, an Mk4 in its normal session (announced), and two upgrade
/// listeners (`listener-a` scripted by `script`, `listener-b` all-acks).
fn mk4_fixture(script: impl Fn(u32) -> Reply + Send + 'static) -> Mk4Fixture {
    let serial = FakeSerial::default();
    let (esp32, mut esp32_end) = serial.add_port("port-esp32");
    let (session, mut session_end) = serial.add_port("port-mk4-session");
    let (a, listener_a) = listener(&serial, "listener-a", script);
    let (b, listener_b) = listener(&serial, "listener-b", ack);
    announce(&mut esp32_end, ESP32, bundle().digest());
    announce(&mut session_end, MK4, mk4_digest());

    let mut manager = UsbSerialManager::new(Box::new(serial)).with_firmware_bin(bundle());
    for _ in 0..4 {
        manager.poll_ports();
    }
    assert_eq!(manager.mk4_upgrade_ports(), ["listener-a", "listener-b"]);
    let ports = vec![
        ("port-esp32", esp32),
        ("port-mk4-session", session),
        ("listener-a", a),
        ("listener-b", b),
    ];
    for (_, port) in &ports {
        port.from_coordinator.lock().unwrap().clear();
    }
    // Handshake residue left where a careless raw read would find it: the first
    // byte of a `MAGIC_REPLY`.
    ports[2].1.to_coordinator.lock().unwrap().push(0x00);
    listener_a.armed.store(true, Ordering::SeqCst);
    listener_b.armed.store(true, Ordering::SeqCst);
    Mk4Fixture {
        manager,
        ports,
        listener_a,
    }
}

impl Mk4Fixture {
    fn run(
        &mut self,
        port: &str,
    ) -> (
        Result<Mk4UpgradeState, Mk4UpgradeError>,
        Vec<Mk4UpgradeState>,
    ) {
        let mut states = vec![];
        let r = self
            .manager
            .run_mk4_upgrade(port, &mk4_image(), |s| states.push(s));
        (r, states)
    }

    /// Every port except `selected` received nothing at all — no frame, no chunk.
    fn assert_untouched_except(&self, selected: Option<&str>) {
        for (name, port) in &self.ports {
            if Some(*name) != selected {
                assert_eq!(
                    written(port),
                    0,
                    "{name} was not selected but received bytes"
                );
            }
        }
    }

    fn chunk_writes(&self) -> Vec<usize> {
        self.listener_a.chunk_writes.lock().unwrap().clone()
    }
}

/// CRITERION: the image stages on the ONE named port, the admission is exactly
/// `PrepareUpgrade2 { size, two-range digest }` + `EnterUpgradeMode`, every
/// chunk is a complete write, and every other port — the ESP32, the Mk4 in
/// session and the second listener — gets zero bytes at either layer.
#[test]
fn an_mk4_image_stages_on_the_selected_listener_and_nowhere_else() {
    let fw = mk4_image();
    let mut f = mk4_fixture(ack);
    let (result, states) = f.run("listener-a");

    let staged = result.expect("every chunk acked");
    assert_eq!(
        staged,
        Mk4UpgradeState::Staged {
            size: fw.size(),
            digest: fw.digest()
        }
    );
    assert!(
        !staged.is_installed(),
        "a staging-only peer never yields installed"
    );
    assert_eq!(states.len(), fw.num_chunks() as usize);
    assert_eq!(
        states.last(),
        Some(&Mk4UpgradeState::Transferring {
            chunks_acked: fw.num_chunks(),
            total_chunks: fw.num_chunks()
        })
    );
    assert_eq!(f.chunk_writes(), vec![4096; fw.num_chunks() as usize]);
    f.assert_untouched_except(Some("listener-a"));

    // What went down the selected port, decoded with the shipped encoding.
    let wire = f.ports[2].1.from_coordinator.lock().unwrap().clone();
    let mut cursor = std::io::Cursor::new(&wire[..]);
    let mut next_upgrade = || -> CoordinatorUpgradeMessage {
        let frame: ReceiveSerial<Upstream> =
            bincode::decode_from_std_read(&mut cursor, frostsnap_comms::BINCODE_CONFIG)
                .expect("an admission frame");
        let ReceiveSerial::Message(m) = frame else {
            panic!("expected a message frame")
        };
        match m.message_body.decode() {
            Some(CoordinatorSendBody::Upgrade(u)) => u,
            other => panic!("expected an upgrade message, got {other:?}"),
        }
    };
    assert!(matches!(
        next_upgrade(),
        CoordinatorUpgradeMessage::PrepareUpgrade2 { size, firmware_digest }
            if size == fw.size() && firmware_digest == fw.digest()
    ));
    assert!(matches!(
        next_upgrade(),
        CoordinatorUpgradeMessage::EnterUpgradeMode
    ));
    let at = cursor.position() as usize;
    assert_eq!(
        &wire[at..],
        fw.as_bytes(),
        "after admission: the image, exactly"
    );

    // The port is dropped after the transfer: it has to re-handshake before it
    // can be selected again, and nothing more is written to it meanwhile.
    assert!(!f
        .manager
        .mk4_upgrade_ports()
        .contains(&"listener-a".to_string()));
    let (again, _) = f.run("listener-a");
    assert!(matches!(again, Err(Mk4UpgradeError::PortNotReady { .. })));
    assert_eq!(
        f.ports[2].1.from_coordinator.lock().unwrap().len(),
        wire.len()
    );
}

/// Exactly one expected `0x11` per chunk: a wrong byte stops the stream there.
#[test]
fn a_wrong_mk4_ack_is_named_and_nothing_follows_it() {
    let mut f = mk4_fixture(|k| Reply::Bytes(vec![if k == 5 { 0x5a } else { 0x11 }]));
    let (result, states) = f.run("listener-a");
    let total = mk4_image().num_chunks();
    assert_eq!(
        result,
        Err(Mk4UpgradeError::Chunk(ChunkError::WrongAck {
            chunk: 5,
            of: total,
            byte: 0x5a
        }))
    );
    assert_eq!(states.len(), 5);
    assert_eq!(f.chunk_writes().len(), 6, "no chunk after the bad ack");
    f.assert_untouched_except(Some("listener-a"));
}

/// Two bytes for one chunk is wrong whatever the second is: a surplus `0x11`
/// would be read as the next chunk's ack and shift every later ack by one, so the
/// "final" ack would be the previous chunk's and not the digest verdict. It is
/// caught at the chunk that produced it, and nothing more is written.
#[test]
fn an_extra_byte_after_an_ack_is_caught_at_its_own_chunk() {
    for extra in [0x00, 0x11] {
        let mut f = mk4_fixture(move |k| {
            Reply::Bytes(if k == 2 { vec![0x11, extra] } else { vec![0x11] })
        });
        let (result, states) = f.run("listener-a");
        assert_eq!(
            result,
            Err(Mk4UpgradeError::Chunk(ChunkError::SurplusAck {
                chunk: 2,
                of: mk4_image().num_chunks(),
                pending: 1
            })),
            "extra byte {extra:#04x}"
        );
        assert_eq!(f.chunk_writes().len(), 3, "no chunk after the surplus");
        assert!(states
            .iter()
            .all(|s| !matches!(s, Mk4UpgradeState::Staged { .. })));
        f.assert_untouched_except(Some("listener-a"));
    }
}

/// A surplus byte that arrives AFTER the final ack (the real verdict behind a
/// shifted one) is caught by the quiet window: never `Staged`.
#[test]
fn a_late_byte_after_the_final_ack_is_not_a_stage() {
    let total = mk4_image().num_chunks();
    let rx: Arc<Mutex<Option<Pipe>>> = Default::default();
    let late = rx.clone();
    let mut f = mk4_fixture(move |k| {
        if k + 1 == total {
            let pipe = late.lock().unwrap().clone().expect("pipe set");
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(30));
                pipe.lock().unwrap().push(0x11);
            });
        }
        Reply::Bytes(vec![0x11])
    });
    *rx.lock().unwrap() = Some(f.ports[2].1.to_coordinator.clone());
    let (result, states) = f.run("listener-a");
    assert_eq!(
        result,
        Err(Mk4UpgradeError::Chunk(ChunkError::SurplusAck {
            chunk: total - 1,
            of: total,
            pending: 1
        }))
    );
    assert!(states
        .iter()
        .all(|s| !matches!(s, Mk4UpgradeState::Staged { .. })));
}

/// A missing ack is named by WHERE it went missing: before admission took,
/// mid-stream, or as the final digest verdict.
#[test]
fn a_missing_mk4_ack_is_named_by_where_it_went_missing() {
    let total = mk4_image().num_chunks();
    let silent_at = |n: u32| {
        move |k: u32| {
            if k == n {
                Reply::Bytes(vec![])
            } else {
                Reply::Bytes(vec![0x11])
            }
        }
    };

    let mut f = mk4_fixture(silent_at(0));
    assert_eq!(f.run("listener-a").0, Err(Mk4UpgradeError::NotAdmitted));
    assert_eq!(f.chunk_writes().len(), 1);

    let mut f = mk4_fixture(silent_at(10));
    assert_eq!(
        f.run("listener-a").0,
        Err(Mk4UpgradeError::Chunk(ChunkError::Timeout {
            chunk: 10,
            of: total
        }))
    );
    assert_eq!(f.chunk_writes().len(), 11);

    let mut f = mk4_fixture(silent_at(total - 1));
    let (result, states) = f.run("listener-a");
    assert_eq!(
        result,
        Err(Mk4UpgradeError::StageNotConfirmed {
            size: mk4_image().size()
        }),
        "every byte sent is not a stage: only the final ack is"
    );
    assert!(states
        .iter()
        .all(|s| !matches!(s, Mk4UpgradeState::Staged { .. })));
    f.assert_untouched_except(Some("listener-a"));
}

#[test]
fn an_mk4_disconnect_is_named() {
    let mut f = mk4_fixture(|k| {
        if k == 7 {
            Reply::HangUp
        } else {
            Reply::Bytes(vec![0x11])
        }
    });
    let (result, _) = f.run("listener-a");
    assert!(
        matches!(
            result,
            Err(Mk4UpgradeError::Chunk(ChunkError::Disconnected {
                chunk: 7,
                ..
            }))
        ),
        "{result:?}"
    );
    assert_eq!(f.chunk_writes().len(), 8);
}

/// Unsupported peers are refused by name before a byte moves: a port with an
/// ESP32 on it, a port with an Mk4 in its normal session (it refuses upgrade
/// messages there and could not say so), and a port that is not ready.
#[test]
fn ports_that_are_not_upgrade_listeners_are_refused_before_any_byte() {
    let mut f = mk4_fixture(ack);
    for port in ["port-esp32", "port-mk4-session"] {
        let (result, _) = f.run(port);
        assert_eq!(
            result,
            Err(Mk4UpgradeError::NotAnUpgradeListener {
                port: port.into(),
                announced: 1
            })
        );
    }
    let (result, _) = f.run("no-such-port");
    assert_eq!(
        result,
        Err(Mk4UpgradeError::PortNotReady {
            port: "no-such-port".into()
        })
    );
    f.assert_untouched_except(None);
    assert_eq!(f.manager.mk4_upgrade_ports(), ["listener-a", "listener-b"]);
}

/// The outcome states cannot be skipped: a reconnect after staging alone is not
/// an installation however its digest reads, and after an install request only
/// the staged digest counts. (A mock of the task-07 peer's half; no peer in
/// this tree can accept an install request.)
#[test]
fn installed_is_only_reachable_through_request_and_matching_reconnect() {
    let fw = mk4_image();
    let staged = Mk4UpgradeState::Staged {
        size: fw.size(),
        digest: fw.digest(),
    };
    assert!(staged.clone().reconnected(MK4, fw.digest()).is_err());

    let requested = staged.install_requested().expect("staged -> requested");
    assert!(!requested.is_installed());
    assert!(requested.clone().install_requested().is_err());
    assert!(requested.clone().reconnected(MK4, mk4_digest()).is_err());
    let installed = requested
        .reconnected(MK4, fw.digest())
        .expect("the staged digest reconnected");
    assert!(installed.is_installed());
}
