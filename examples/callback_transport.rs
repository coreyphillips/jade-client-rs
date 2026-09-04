//! A [`JadeTransport`] the host platform drives.
//!
//! This is the shape a mobile application wants. The platform owns the
//! Bluetooth connection, because permissions, pairing, backgrounding and
//! lifecycle all belong there, and Rust only moves bytes across the boundary.
//! It is also the only shape available on iOS, which has no Rust Bluetooth
//! backend at all.
//!
//! Two directions cross the boundary:
//!
//! - Host to device: [`BleLink::write_chunk`], which the platform implements.
//! - Device to host: [`CallbackTransport::on_notify`], which the platform calls
//!   once per GATT notification.
//!
//! Run it with `cargo run --example callback_transport`. The demo at the bottom
//! wires the transport to a scripted link rather than a radio, so it exercises
//! the whole path with no hardware.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jade_client_rs::{Jade, JadeError, JadeTransport, MAX_CHUNK_BYTES};
use tokio::sync::{mpsc, Mutex};

// ============================================================================
// The part to copy
// ============================================================================

/// The half of the link the platform owns.
///
/// In a UniFFI binding this becomes a callback interface implemented in Swift
/// or Kotlin. Both methods are called from a blocking context, so they may
/// wait on the platform's own BLE callbacks.
pub trait BleLink: Send + Sync + 'static {
    /// Write one chunk to the Nordic UART write characteristic
    /// (`6e400002-b5a3-f393-e0a9-e50e24dcca9e`), **with response**.
    ///
    /// Must not return until the peripheral has acknowledged the write, and
    /// must not reorder chunks. Write-without-response silently drops chunks on
    /// the ESP32 GATT stack, and a reordered chunk corrupts the frame.
    ///
    /// On iOS that means `writeValue(_:for:type:.withResponse)` and waiting for
    /// `peripheral(_:didWriteValueFor:error:)`. On Android it means
    /// `WRITE_TYPE_DEFAULT` and waiting for `onCharacteristicWrite`.
    fn write_chunk(&self, chunk: &[u8]) -> Result<(), String>;

    /// Tear the connection down. Safe to call more than once.
    ///
    /// Do this even on an abrupt shutdown. A Jade whose central vanished
    /// without disconnecting can refuse new connections until it is power
    /// cycled.
    fn disconnect(&self);
}

/// A transport that hands writes to the platform and receives notifications
/// back through [`CallbackTransport::on_notify`].
pub struct CallbackTransport {
    link: Arc<dyn BleLink>,
    /// Notifications the platform has delivered but the client has not read.
    /// Unbounded because dropping a notification loses part of a frame, and
    /// there is no way to ask the device to resend it.
    inbound: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    notifier: mpsc::UnboundedSender<Vec<u8>>,
    chunk_bytes: usize,
}

impl std::fmt::Debug for CallbackTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackTransport")
            .field("chunk_bytes", &self.chunk_bytes)
            .finish_non_exhaustive()
    }
}

impl CallbackTransport {
    /// Wrap a platform link.
    ///
    /// `max_write_len` is what the platform reports it can put in one write:
    /// `maximumWriteValueLength(for: .withResponse)` on iOS, or the negotiated
    /// ATT MTU minus three on Android. It is clamped into
    /// `1..=MAX_CHUNK_BYTES`, since a zero would stall the write loop and the
    /// link layer rejects anything larger.
    pub fn new(link: Arc<dyn BleLink>, max_write_len: usize) -> Arc<Self> {
        let (notifier, inbound) = mpsc::unbounded_channel();
        Arc::new(Self {
            link,
            inbound: Mutex::new(inbound),
            notifier,
            chunk_bytes: max_write_len.clamp(1, MAX_CHUNK_BYTES as usize),
        })
    }

    /// Feed one GATT notification from the notify characteristic
    /// (`6e400003-b5a3-f393-e0a9-e50e24dcca9e`) to the client.
    ///
    /// Call this for every notification, in arrival order, from
    /// `didUpdateValueFor` on iOS or `onCharacteristicChanged` on Android.
    /// Frames are not aligned to notifications: one reply can span several, and
    /// one notification can carry the tail of one reply and the head of the
    /// next. The client reassembles, so pass the bytes through untouched.
    pub fn on_notify(&self, data: Vec<u8>) {
        // A send failure only means the client is gone, which close() handles.
        let _ = self.notifier.send(data);
    }

    pub fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }
}

#[async_trait]
impl JadeTransport for CallbackTransport {
    async fn write_all(&self, data: Vec<u8>) -> Result<(), JadeError> {
        let link = Arc::clone(&self.link);
        let chunk_bytes = self.chunk_bytes;

        // One blocking task for the whole request, not one per chunk. The
        // firmware discards a partially received message after two seconds of
        // silence, three on Jade v1, so the chunks of a single request must not
        // be separated by a scheduling gap. A 16 KiB PSBT is roughly 32 writes.
        tokio::task::spawn_blocking(move || {
            for chunk in data.chunks(chunk_bytes) {
                link.write_chunk(chunk).map_err(JadeError::transport)?;
            }
            Ok(())
        })
        .await
        .map_err(|error| JadeError::IoError {
            error_details: format!("ble write task failed: {error}"),
        })?
    }

    async fn read_some(&self, timeout: Duration) -> Result<Vec<u8>, JadeError> {
        let mut inbound = self.inbound.lock().await;
        match tokio::time::timeout(timeout, inbound.recv()).await {
            Ok(Some(bytes)) => Ok(bytes),
            // Every sender is gone, so the transport itself has been dropped.
            Ok(None) => Err(JadeError::DeviceDisconnected),
            // Nothing arrived, which is the normal state while the user is
            // deciding on the device. An empty vector is not an error.
            Err(_) => Ok(Vec::new()),
        }
    }

    async fn close(&self) -> Result<(), JadeError> {
        self.link.disconnect();
        Ok(())
    }
}

// ============================================================================
// A scripted link, so the example runs without a radio
// ============================================================================

/// Answers requests the way a Jade would, to show the wiring end to end.
///
/// It buffers chunks until they form a complete CBOR item, which is what a real
/// device does too, and is why the chunk size above is invisible to the client.
struct ScriptedLink {
    partial: std::sync::Mutex<Vec<u8>>,
    transport: std::sync::Mutex<Option<std::sync::Weak<CallbackTransport>>>,
}

#[derive(serde::Deserialize)]
struct SeenRequest {
    id: String,
    method: String,
}

impl ScriptedLink {
    fn reply_to(request: &SeenRequest) -> Option<ciborium::Value> {
        let text = |v: &str| ciborium::Value::Text(v.to_string());
        let result = match request.method.as_str() {
            "get_version_info" => ciborium::Value::Map(vec![
                (text("JADE_VERSION"), text("1.0.41")),
                (text("JADE_STATE"), text("LOCKED")),
                (text("JADE_NETWORKS"), text("MAIN")),
                (text("JADE_HAS_PIN"), ciborium::Value::Bool(true)),
            ]),
            "add_entropy" => ciborium::Value::Bool(true),
            "ping" => ciborium::Value::Integer(0.into()),
            _ => return None,
        };
        Some(ciborium::Value::Map(vec![
            (text("id"), text(&request.id)),
            (text("result"), result),
        ]))
    }
}

impl BleLink for ScriptedLink {
    fn write_chunk(&self, chunk: &[u8]) -> Result<(), String> {
        let mut partial = self.partial.lock().unwrap();
        partial.extend_from_slice(chunk);

        // Wait for a whole request before answering, exactly as the device does.
        let Ok(request) = ciborium::from_reader::<SeenRequest, _>(partial.as_slice()) else {
            return Ok(());
        };
        partial.clear();
        println!("  [link] answering {}", request.method);

        let Some(reply) = Self::reply_to(&request) else {
            return Err(format!(
                "scripted link has no answer for {}",
                request.method
            ));
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&reply, &mut encoded).map_err(|e| e.to_string())?;

        // Deliver in small pieces, to show that a reply need not arrive whole.
        if let Some(transport) = self
            .transport
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|w| w.upgrade())
        {
            for piece in encoded.chunks(8) {
                transport.on_notify(piece.to_vec());
            }
        }
        Ok(())
    }

    fn disconnect(&self) {
        println!("  [link] disconnected");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let link = Arc::new(ScriptedLink {
        partial: std::sync::Mutex::new(Vec::new()),
        transport: std::sync::Mutex::new(None),
    });

    // 244 is a common Android ATT MTU of 247 minus three. A real caller passes
    // whatever the platform reports.
    let transport = CallbackTransport::new(link.clone(), 244);
    *link.transport.lock().unwrap() = Some(Arc::downgrade(&transport));
    println!("chunk size {} bytes", transport.chunk_bytes());

    let mut jade = Jade::connect(transport as Arc<dyn JadeTransport>).await?;
    println!("version {}", jade.version_info().jade_version);
    println!("state   {:?}", jade.version_info().jade_state);
    println!("ping    {:?}", jade.ping().await?);

    jade.close().await?;
    Ok(())
}
