use frostsnap_comms::{
    DeviceSupportedFeatures, Direction, Downstream, MagicBytes, ReceiveSerial, BINCODE_CONFIG,
};
pub use serialport;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::marker::PhantomData;
use tracing::{event, Level};

pub type SerialPort = Box<dyn serialport::SerialPort>;

// NOTE: This trait is not really necessary anymore because it seesm the serialport library works on
// enough platforms that we could just use it everywhere. This trait is sticking around because it's
// work to remove and maybe I'm wrong.
pub trait Serial: Send {
    fn available_ports(&self) -> Vec<PortDesc>;
    fn open_device_port(
        &self,
        unique_id: &str,
        baud_rate: u32,
    ) -> Result<SerialPort, PortOpenError>;
}

#[derive(Debug)]
pub enum PortOpenError {
    DeviceBusy,
    PermissionDenied,
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl core::fmt::Display for PortOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortOpenError::DeviceBusy => write!(f, "device is busy"),
            PortOpenError::PermissionDenied => write!(f, "permission denied"),
            PortOpenError::Other(error) => write!(f, "{error}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortDesc {
    pub id: String,
    pub vid: u16,
    pub pid: u16,
}

pub struct FramedSerialPort<D: Direction = Downstream> {
    conch_enabled: bool,
    magic_bytes_progress: usize,
    has_sent_conch: bool,
    inner: BufReader<SerialPort>,
    send_queue: VecDeque<<D::Opposite as Direction>::RecvType>,
    directions: PhantomData<D>,
}

impl<D: Direction> FramedSerialPort<D> {
    pub fn new(port: SerialPort) -> Self {
        Self {
            inner: BufReader::new(port),
            has_sent_conch: false,
            conch_enabled: false,
            magic_bytes_progress: 0,
            send_queue: Default::default(),
            directions: Default::default(),
        }
    }

    pub fn anything_to_read(&self) -> bool {
        match self.inner.get_ref().bytes_to_read() {
            Ok(len) => len > 0,
            // just say there's something there to get the caller to read and get the error rather than returing it here
            Err(_) => true,
        }
    }

    pub fn read_for_magic_bytes(
        &mut self,
    ) -> Result<Option<DeviceSupportedFeatures>, std::io::Error> {
        if !self.anything_to_read() {
            return Ok(None);
        }
        self.inner.fill_buf()?;
        let mut consumed = 0;
        let (progress, found) = frostsnap_comms::make_progress_on_magic_bytes::<D>(
            self.inner
                .buffer()
                .iter()
                .cloned()
                .inspect(|_| consumed += 1),
            self.magic_bytes_progress,
        );
        self.inner.consume(consumed);
        self.magic_bytes_progress = progress;
        let supported_features = found.map(DeviceSupportedFeatures::from_version);
        Ok(supported_features)
    }

    pub fn queue_send(&mut self, message: <D::Opposite as Direction>::RecvType) {
        self.send_queue.push_back(message);
    }

    pub fn write_magic_bytes(&mut self) -> Result<(), bincode::error::EncodeError> {
        self.raw_send(ReceiveSerial::<D::Opposite>::MagicBytes(
            MagicBytes::default(),
        ))
    }

    pub fn try_read_message(
        &mut self,
    ) -> Result<Option<ReceiveSerial<D>>, bincode::error::DecodeError> {
        if !self.anything_to_read() && self.inner.buffer().is_empty() {
            return Ok(None);
        }

        let message = bincode::decode_from_reader(&mut self.inner, BINCODE_CONFIG)?;

        match &message {
            ReceiveSerial::MagicBytes(_) => { /* magic bytes doesn't count as a message */ }
            ReceiveSerial::Message(_) | ReceiveSerial::Conch => {
                // if we receive a message we count it as the conch
                use frostsnap_core::Gist;
                self.has_sent_conch = false;
                event!(Level::TRACE, gist = message.gist(), "GOT CONCH");
            }
            _ => { /* other messages (like reset are not a conch) */ }
        };

        Ok(Some(message))
    }

    pub fn raw_write(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
        let io_device = self.inner.get_mut();
        io_device.write_all(bytes)?;
        io_device.flush()?;
        Ok(())
    }

    pub fn raw_read(&mut self, bytes: &mut [u8]) -> Result<(), std::io::Error> {
        self.inner.read_exact(bytes)?;
        Ok(())
    }

    /// Throw away every byte already received: the `BufReader`'s fill AND whatever
    /// the port has queued. Returns how many bytes went.
    ///
    /// For the framed-to-raw switch. `read_for_magic_bytes` consumes only up to the
    /// first `MAGIC_REPLY` it matches and `anything_to_read` asks the PORT, not the
    /// buffer, so a second reply can sit in the fill forever — and the first raw
    /// byte read after it (`MAGIC_REPLY` starts `0x00`) would be taken as an ack.
    /// Does not wait: bytes still in flight are not seen here.
    pub fn discard_input(&mut self) -> Result<usize, std::io::Error> {
        let mut dropped = 0;
        loop {
            let buffered = self.inner.buffer().len();
            self.inner.consume(buffered);
            dropped += buffered;
            if self.inner.get_ref().bytes_to_read()? == 0 {
                return Ok(dropped);
            }
            self.inner.fill_buf()?;
        }
    }

    /// How many received bytes are waiting: the `BufReader`'s fill plus what the
    /// port has queued. Does not read or wait.
    pub fn pending_input(&self) -> Result<usize, std::io::Error> {
        Ok(self.inner.buffer().len() + self.inner.get_ref().bytes_to_read()? as usize)
    }

    pub fn discard_all_messages(&mut self) -> Result<(), bincode::error::DecodeError> {
        while self.anything_to_read() || !self.inner.buffer().is_empty() {
            let _message: ReceiveSerial<D> =
                bincode::decode_from_reader(&mut self.inner, BINCODE_CONFIG)?;
        }

        Ok(())
    }

    pub fn has_conch(&self) -> bool {
        !self.has_sent_conch
    }

    pub fn set_conch_enabled(&mut self, enabled: bool) {
        if self.conch_enabled != enabled {
            self.conch_enabled = enabled;
            self.has_sent_conch = false;
        }
    }

    pub fn wait_for_conch(&mut self) -> Result<(), bincode::error::DecodeError> {
        if self.conch_enabled && !self.has_conch() {
            while !self.has_conch() {
                let _ = self.try_read_message()?;
            }
        }
        Ok(())
    }

    pub fn raw_send(
        &mut self,
        frame: ReceiveSerial<D::Opposite>,
    ) -> Result<(), bincode::error::EncodeError> {
        bincode::encode_into_std_write(frame, self.inner.get_mut(), BINCODE_CONFIG)?;
        self.inner.get_mut().flush().map_err(|e| {
            bincode::error::EncodeError::OtherString(format!("failed to flush: {e}"))
        })?;
        Ok(())
    }

    pub fn poll_send(&mut self) -> Result<(), bincode::error::EncodeError> {
        if self.conch_enabled && self.has_sent_conch {
            return Ok(());
        }

        if let Some(message) = self.send_queue.pop_front() {
            use frostsnap_core::Gist;
            event!(Level::DEBUG, gist = message.gist(), "sending message");
            self.raw_send(ReceiveSerial::<D::Opposite>::Message(message))?;
        }

        if self.conch_enabled && !self.has_sent_conch {
            event!(Level::TRACE, "SENDING CONCH");
            self.raw_send(ReceiveSerial::<D::Opposite>::Conch)?;
            self.has_sent_conch = true;
        }

        Ok(())
    }
}

use std::time::Duration;

/// impl using the serialport crate
#[derive(Clone, Default, Debug)]
pub struct DesktopSerial;

impl Serial for DesktopSerial {
    fn available_ports(&self) -> Vec<PortDesc> {
        let mut ports: Vec<PortDesc> = serialport::available_ports()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|port| match port.port_type {
                serialport::SerialPortType::UsbPort(usb_port) => Some(PortDesc {
                    id: port.port_name,
                    vid: usb_port.vid,
                    pid: usb_port.pid,
                }),
                _ => None,
            })
            .collect();

        // On macOS, filter duplicate tty/cu devices
        if cfg!(target_os = "macos") {
            use std::collections::HashSet;

            // Find all device numbers that have cu versions
            let cu_device_numbers: HashSet<String> = ports
                .iter()
                .filter(|p| p.id.starts_with("/dev/cu."))
                .filter_map(|p| {
                    // Extract device number after "cu."
                    p.id.strip_prefix("/dev/cu.").map(|s| s.to_string())
                })
                .collect();

            // Keep only cu devices when both exist, otherwise keep tty
            ports.retain(|p| {
                if let Some(device_num) = p.id.strip_prefix("/dev/tty.") {
                    // This is a tty device - only keep if no corresponding cu device exists
                    !cu_device_numbers.contains(device_num)
                } else {
                    // Keep all non-tty devices (including cu devices)
                    true
                }
            });
        }

        ports
    }

    fn open_device_port(&self, id: &str, baud_rate: u32) -> Result<SerialPort, PortOpenError> {
        serialport::new(id, baud_rate)
            // This timeout should never be hit in any normal circumstance but it's important to
            // have in case a device is bisbehaving. Note: 10ms is too low and leads to errors when
            // writing.
            .timeout(Duration::from_millis(5_000))
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

/// One port, named by the caller, and nothing else: the updater CLI's transport.
///
/// NEVER DISCOVERS. `available_ports` is exactly the path given, so nothing a
/// `UsbSerialManager` does can reach a port the operator did not name — no
/// auto-selection of whatever happens to be plugged in. It declares the cold-snap
/// VID/PID for that one path because naming it IS the operator's declaration.
///
/// Opened at baud 0: USB CDC has no line rate, and on macOS a non-zero rate is an
/// IOSSIOSPEED ioctl that fails with ENOTTY on a pty (`serialport`'s own
/// posix/termios.rs), which would make the CLI untestable on virtual ports.
#[derive(Clone, Debug)]
pub struct ExplicitPort {
    path: String,
}

impl ExplicitPort {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

impl Serial for ExplicitPort {
    fn available_ports(&self) -> Vec<PortDesc> {
        vec![PortDesc {
            id: self.path.clone(),
            vid: crate::usb_serial_manager::USB_VID,
            pid: crate::usb_serial_manager::USB_PID,
        }]
    }

    fn open_device_port(&self, id: &str, _baud_rate: u32) -> Result<SerialPort, PortOpenError> {
        if id != self.path {
            return Err(PortOpenError::Other(
                format!("{id} is not the port this updater was told to use").into(),
            ));
        }
        serialport::new(id, 0)
            .timeout(Duration::from_millis(5_000))
            .open()
            .map_err(|e| PortOpenError::Other(Box::new(e)))
    }
}

impl<T: Serial + Sync> Serial for std::sync::Arc<T> {
    fn available_ports(&self) -> Vec<PortDesc> {
        self.as_ref().available_ports()
    }

    fn open_device_port(
        &self,
        unique_id: &str,
        baud_rate: u32,
    ) -> Result<SerialPort, PortOpenError> {
        self.as_ref().open_device_port(unique_id, baud_rate)
    }
}
