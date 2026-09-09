//! USB CDC serial transport.
//!
//! Behind the `serial` feature. iOS has no USB serial backend, and on Android
//! the host application normally drives USB itself, so a mobile consumer should
//! turn this feature off and supply its own [`crate::JadeTransport`].

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serialport::SerialPort;

use crate::error::JadeError;
use crate::transport::JadeTransport;
use crate::types::{JadeDeviceInfo, JadeTransportKind};

/// Jade's serial link speed.
const BAUD_RATE: u32 = 115_200;

/// Serial has no MTU, but chunking keeps writes off the stack and matches the
/// Bluetooth path closely enough that both exercise the same code.
const CHUNK_BYTES: usize = 509;

/// USB vendor and product pairs seen on Jade and Jade Plus units, including the
/// bridge chips used by DIY builds.
const KNOWN_USB_IDS: &[(u16, u16)] = &[
    (0x10c4, 0xea60), // Silicon Labs CP210x, Jade v1
    (0x1a86, 0x55d4), // WCH CH9102
    (0x0403, 0x6001), // FTDI FT232
    (0x1a86, 0x7523), // WCH CH340
    (0x303a, 0x4001), // Espressif native USB, Jade Plus
    (0x303a, 0x1001), // Espressif USB serial/JTAG
];

/// Discover attached Jade units.
///
/// Only ports whose USB descriptor matches a known Jade bridge are returned, so
/// a modem or GPS receiver on the same machine is not offered as a Jade.
pub fn enumerate_devices() -> Vec<JadeDeviceInfo> {
    // serialport's Linux path without libudev reads /sys/class/tty and panics
    // outright if it is missing. A wallet library must not carry that risk.
    #[cfg(target_os = "linux")]
    if !std::path::Path::new("/sys/class/tty").exists() {
        log::warn!("[jade] /sys/class/tty is missing, skipping serial enumeration");
        return Vec::new();
    }

    let ports = match serialport::available_ports() {
        Ok(ports) => ports,
        Err(error) => {
            log::warn!("[jade] could not enumerate serial ports: {error}");
            return Vec::new();
        }
    };

    ports
        .into_iter()
        .filter_map(|port| {
            let serialport::SerialPortType::UsbPort(info) = port.port_type else {
                return None;
            };
            if !KNOWN_USB_IDS.contains(&(info.vid, info.pid)) {
                return None;
            }
            // macOS exposes every USB serial device twice: /dev/cu.* is the
            // call-out node and /dev/tty.* the dial-in one. Opening the dial-in
            // node blocks until carrier detect is asserted, which never happens
            // on a Jade, so offering it would hand the caller a path that hangs.
            #[cfg(target_os = "macos")]
            if !port.port_name.starts_with("/dev/cu.") {
                return None;
            }
            Some(JadeDeviceInfo {
                path: port.port_name,
                transport: JadeTransportKind::Serial,
                name: info.product.clone(),
                serial_number: info.serial_number.clone(),
            })
        })
        .collect()
}

/// A serial link to a device.
#[derive(Debug)]
pub struct SerialTransport {
    /// A std mutex rather than a tokio one: the guard is taken inside
    /// `spawn_blocking`, where a tokio guard could not be held.
    port: Arc<Mutex<Option<Box<dyn SerialPort>>>>,
    /// What `clears_modem_lines` decided for this path, so close matches open.
    clear_lines: bool,
}

/// Whether DTR and RTS have to be cleared for `path`.
///
/// On the bridge chips above these lines drive the ESP32's EN and BOOT pins, so
/// the wrong state reboots the device or holds it in reset. The correct state is
/// not fixed, it depends on which device node is being opened, and the reference
/// implementation keys off exactly this prefix:
///
/// - `/dev/tty*`, the Linux node and the macOS dial-in node, needs both cleared,
///   because the kernel asserts them on open and that reboots the hardware.
/// - `/dev/cu.*`, the macOS call-out node, needs both left asserted. Clearing
///   them there stops the device answering at all, and it stays unresponsive
///   until it is power cycled.
pub(crate) fn clears_modem_lines(path: &str) -> bool {
    path.starts_with("/dev/tty")
}

impl SerialTransport {
    pub fn open(path: &str) -> Result<Self, JadeError> {
        let clear_lines = clears_modem_lines(path);

        let mut port = serialport::new(path, BAUD_RATE)
            .timeout(Duration::from_millis(250))
            .dtr_on_open(!clear_lines)
            .open()
            .map_err(|error| JadeError::ConnectionError {
                error_details: format!("could not open {path}: {error}"),
            })?;

        if let Err(error) = port.write_request_to_send(!clear_lines) {
            log::warn!("[jade] could not set RTS on {path}: {error}");
        }

        Ok(Self {
            port: Arc::new(Mutex::new(Some(port))),
            clear_lines,
        })
    }
}

#[async_trait]
impl JadeTransport for SerialTransport {
    async fn write_all(&self, data: Vec<u8>) -> Result<(), JadeError> {
        let port = Arc::clone(&self.port);
        tokio::task::spawn_blocking(move || {
            let mut port = port
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let port = port.as_mut().ok_or(JadeError::DeviceDisconnected)?;
            for chunk in data.chunks(CHUNK_BYTES) {
                std::io::Write::write_all(&mut **port, chunk).map_err(|error| {
                    JadeError::transport(format!("serial write failed: {error}"))
                })?;
            }
            std::io::Write::flush(&mut **port)
                .map_err(|error| JadeError::transport(format!("serial flush failed: {error}")))
        })
        .await
        .map_err(|error| JadeError::IoError {
            error_details: format!("serial write task failed: {error}"),
        })?
    }

    async fn read_some(&self, timeout: Duration) -> Result<Vec<u8>, JadeError> {
        let port = Arc::clone(&self.port);
        tokio::task::spawn_blocking(move || {
            let mut port = port
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let port = port.as_mut().ok_or(JadeError::DeviceDisconnected)?;
            if let Err(error) = port.set_timeout(timeout) {
                log::debug!("[jade] could not set the serial timeout: {error}");
            }

            let mut buffer = vec![0u8; 4096];
            match std::io::Read::read(&mut **port, &mut buffer) {
                Ok(read) => {
                    buffer.truncate(read);
                    Ok(buffer)
                }
                // A timeout means nothing arrived, which is the normal state
                // while the user is deciding on the device.
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(Vec::new()),
                Err(error) => Err(JadeError::transport(format!("serial read failed: {error}"))),
            }
        })
        .await
        .map_err(|error| JadeError::IoError {
            error_details: format!("serial read task failed: {error}"),
        })?
    }

    async fn close(&self) -> Result<(), JadeError> {
        let port = Arc::clone(&self.port);
        let clear_lines = self.clear_lines;
        tokio::task::spawn_blocking(move || {
            let mut port = port
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(mut port) = port.take() else {
                return;
            };
            // Only where open cleared them. Dropping the lines on a call-out
            // node leaves the device unresponsive until it is power cycled.
            if clear_lines {
                let _ = port.write_data_terminal_ready(false);
                let _ = port.write_request_to_send(false);
            }
            drop(port);
        })
        .await
        .map_err(|error| JadeError::IoError {
            error_details: format!("serial close task failed: {error}"),
        })
    }
}
