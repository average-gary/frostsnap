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
use std::sync::{Arc, Mutex};

// From `usb_serial_manager.rs` — a port is ignored unless it matches.
const USB_VID: u16 = 12346;
const USB_PID: u16 = 4097;

/// One direction of one port.
type Pipe = Arc<Mutex<Vec<u8>>>;

/// A port end: reads from `rx`, writes to `tx`.
struct FakePortEnd {
    name: String,
    rx: Pipe,
    tx: Pipe,
}

impl Read for FakePortEnd {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut rx = self.rx.lock().unwrap();
        let n = buf.len().min(rx.len());
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

#[derive(Default, Clone)]
struct FakeSerial {
    ports: Arc<Mutex<Vec<(String, Pipe, Pipe)>>>,
}

impl FakeSerial {
    /// Register a port and hand back the device end of it.
    fn add_port(&self, name: &str) -> (MockPort, FramedSerialPort<Upstream>) {
        let from_coordinator: Pipe = Default::default();
        let to_coordinator: Pipe = Default::default();
        self.ports.lock().unwrap().push((
            name.to_string(),
            to_coordinator.clone(),
            from_coordinator.clone(),
        ));
        let device_end = FakePortEnd {
            name: format!("{name}:device"),
            rx: from_coordinator.clone(),
            tx: to_coordinator.clone(),
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
            .map(|(name, _, _)| PortDesc {
                id: name.clone(),
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
        let (name, rx, tx) = ports
            .iter()
            .find(|(name, _, _)| name == unique_id)
            .expect("port exists");
        Ok(Box::new(FakePortEnd {
            name: name.clone(),
            rx: rx.clone(),
            tx: tx.clone(),
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
