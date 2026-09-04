# Bluetooth

This crate ships no Bluetooth transport. BLE permissions, pairing, backgrounding
and lifecycle belong to the host platform, not to a protocol crate, so
[`JadeTransport`] is the seam and the link itself is yours to supply.

This page is what you need to write one.

## Which shape to use

| Target | Who owns the radio | Reference |
|---|---|---|
| iOS | The app, in Swift | [`examples/callback_transport.rs`](../examples/callback_transport.rs) |
| Android | The app, in Kotlin | [`examples/callback_transport.rs`](../examples/callback_transport.rs) |
| macOS, Linux, Windows tooling | Rust, via `btleplug` | [below](#a-btleplug-implementation) |

For a mobile application the callback shape is the only practical one. There is
no Rust Bluetooth backend for iOS at all, and the Android backends need JNI
plumbing you would rather not own. Let the platform drive CoreBluetooth or
Android BLE, and move bytes across the boundary.

`btleplug` is worth it for desktop tooling and for testing the protocol against
real hardware from a Rust test harness, which is how the hardware verification
below was done.

## The service

Jade speaks the Nordic UART Service.

| Role | UUID |
|---|---|
| Service | `6e400001-b5a3-f393-e0a9-e50e24dcca9e` |
| Write, host to Jade | `6e400002-b5a3-f393-e0a9-e50e24dcca9e` |
| Notify, Jade to host | `6e400003-b5a3-f393-e0a9-e50e24dcca9e` |

Units advertise as `Jade <suffix>`, for example `Jade 8F6B64`, where the suffix
is the tail of the device's MAC. Scan filtered on the service UUID rather than
on the name.

## The rules

Each of these fails only against real hardware, and each fails in a way that
looks like something else.

1. **Write with response.** Write-without-response silently drops chunks on the
   ESP32 GATT stack. There is no error; the request simply never completes.
2. **Do not pause between the chunks of one request.** The firmware discards a
   partially received message after two seconds of silence, three on Jade v1,
   and answers with an error it cannot attribute to a request id. Write the
   chunks of one request in a single loop, not one per scheduler tick.
3. **Clamp the chunk size** into `1..=MAX_CHUNK_BYTES`, which is 509. Zero
   stalls the write loop and the link layer rejects anything larger.
4. **Pass notifications through untouched, in order.** Frames are not aligned to
   notifications. One reply can span several, and one notification can carry the
   tail of one reply and the head of the next. The client reassembles.
5. **Disconnect on the way out, signals included.** A Jade whose central
   vanished without disconnecting can refuse new connections until it is
   physically power cycled.

Writes may take as long as they need. The deadline a caller passes covers the
write as well as the reply, so a stalled link surfaces as `JadeError::Timeout`
rather than as an operation that never returns.

## Chunk size

Ask the platform, do not guess:

- iOS: `peripheral.maximumWriteValueLength(for: .withResponse)`
- Android: the negotiated ATT MTU minus three
- `btleplug`: not exposed, so pick a conservative value

Then clamp into `1..=MAX_CHUNK_BYTES`. Against a Jade v1 the full 509 bytes
works, and so does a pathological chunk size of 1; the client does not care,
because the device reassembles.

## A btleplug implementation

Verified against a Jade v1 on firmware 1.0.41, from macOS. It is not compiled by
CI, since the crate does not depend on `btleplug`. Add `btleplug`, `futures`,
`uuid` and `tokio` to use it.

```rust
use std::time::Duration;

use async_trait::async_trait;
use btleplug::api::{
    Central, CentralEvent, CharPropFlags, Characteristic, Manager as _, Peripheral as _,
    ScanFilter, WriteType,
};
use btleplug::platform::{Manager, Peripheral};
use futures::StreamExt;
use jade_client_rs::{JadeError, JadeTransport, MAX_CHUNK_BYTES};
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

pub const NUS_SERVICE: Uuid = Uuid::from_u128(0x6e400001_b5a3_f393_e0a9_e50e24dcca9e);
pub const NUS_WRITE: Uuid = Uuid::from_u128(0x6e400002_b5a3_f393_e0a9_e50e24dcca9e);
pub const NUS_NOTIFY: Uuid = Uuid::from_u128(0x6e400003_b5a3_f393_e0a9_e50e24dcca9e);

fn err(details: impl std::fmt::Display) -> JadeError {
    JadeError::transport(details)
}

pub struct BleTransport {
    peripheral: Peripheral,
    write_char: Characteristic,
    rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    chunk_bytes: usize,
}

impl BleTransport {
    pub async fn discover(scan_secs: u64, chunk_bytes: usize) -> Result<Self, JadeError> {
        let manager = Manager::new().await.map_err(err)?;
        let central = manager
            .adapters()
            .await
            .map_err(err)?
            .into_iter()
            .next()
            .ok_or_else(|| err("no bluetooth adapter"))?;

        // Take the peripheral from this scan's own event stream rather than
        // from central.peripherals(). See the macOS note below.
        let mut events = central.events().await.map_err(err)?;
        central
            .start_scan(ScanFilter { services: vec![NUS_SERVICE] })
            .await
            .map_err(err)?;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(scan_secs);
        let mut found = None;
        while found.is_none() {
            let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.next()).await else {
                break;
            };
            let (CentralEvent::DeviceDiscovered(id) | CentralEvent::DeviceUpdated(id)) = event
            else {
                continue;
            };
            let Ok(peripheral) = central.peripheral(&id).await else { continue };
            let Ok(Some(props)) = peripheral.properties().await else { continue };
            if props.services.contains(&NUS_SERVICE)
                && props.local_name.unwrap_or_default().starts_with("Jade")
            {
                found = Some(peripheral);
            }
        }
        let _ = central.stop_scan().await;
        let peripheral = found.ok_or_else(|| err("no Jade advertising the NUS service"))?;

        // A stale handle makes connect() block indefinitely rather than fail.
        match tokio::time::timeout(Duration::from_secs(20), peripheral.connect()).await {
            Ok(result) => result.map_err(err)?,
            Err(_) => return Err(err("timed out connecting to the Jade")),
        }
        peripheral.discover_services().await.map_err(err)?;

        let chars = peripheral.characteristics();
        let write_char = chars
            .iter()
            .find(|c| c.uuid == NUS_WRITE)
            .ok_or_else(|| err("no NUS write characteristic"))?
            .clone();
        let notify_char = chars
            .iter()
            .find(|c| c.uuid == NUS_NOTIFY)
            .ok_or_else(|| err("no NUS notify characteristic"))?
            .clone();

        // Rule 1. WRITE is write-with-response; WRITE_WITHOUT_RESPONSE is not.
        if !write_char.properties.contains(CharPropFlags::WRITE) {
            return Err(err("write characteristic does not support write with response"));
        }

        peripheral.subscribe(&notify_char).await.map_err(err)?;
        let mut stream = peripheral.notifications().await.map_err(err)?;
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(notification) = stream.next().await {
                if notification.uuid == NUS_NOTIFY && tx.send(notification.value).is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            peripheral,
            write_char,
            rx: Mutex::new(rx),
            chunk_bytes: chunk_bytes.clamp(1, MAX_CHUNK_BYTES as usize),
        })
    }
}

#[async_trait]
impl JadeTransport for BleTransport {
    async fn write_all(&self, data: Vec<u8>) -> Result<(), JadeError> {
        // Rule 2: no pause between the chunks of one request.
        for chunk in data.chunks(self.chunk_bytes) {
            self.peripheral
                .write(&self.write_char, chunk, WriteType::WithResponse)
                .await
                .map_err(|e| err(format!("ble write failed: {e}")))?;
        }
        Ok(())
    }

    async fn read_some(&self, timeout: Duration) -> Result<Vec<u8>, JadeError> {
        let mut rx = self.rx.lock().await;
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(value)) => Ok(value),
            Ok(None) => Err(err("ble notification stream ended")),
            // Nothing arrived, which is normal while the user decides.
            Err(_) => Ok(Vec::new()),
        }
    }

    async fn close(&self) -> Result<(), JadeError> {
        self.peripheral.disconnect().await.map_err(err)
    }
}
```

## macOS

Two things will cost you an afternoon, neither of them this crate's doing.

**The peripheral identifier rotates.** Jade advertises from a resolvable private
address, so CoreBluetooth hands out a different `PeripheralId` for the same
physical device between scans. A cached list therefore fills with stale handles,
and connecting to a stale one hangs rather than failing. Take the peripheral
from the scan that is running now, which is what the code above does, and put a
timeout on `connect` regardless.

**An abrupt exit wedges the device.** Killing a process that holds an open
connection leaves the Jade advertising but refusing every connection, and it
does not recover on its own. Not from a host Bluetooth toggle, and not from the
usual ESP32 reset sequences. Only a physical power cycle clears it. Handle
`SIGTERM` and ctrl-c and disconnect before exiting.

## What has been verified on hardware

Against a Jade v1 on firmware 1.0.41, over BLE from macOS, in one session:

- Connect, `get_version_info`, `add_entropy`, `ping`
- Unlock through the pinserver, with the PIN entered on the device
- Account export for `wpkh` and `tr`
- Address verification, matching a locally derived address
- Message signing, with the recovered public key matching the derived one
- PSBT signing, single input
- PSBT signing, 20 inputs: a 2921 byte request written as six chunks, five of
  them the full 509 bytes, and a 5005 byte reply returned in two fragments
  reassembled through `get_extended_data`

Chunk sizes of 1 and 509 both worked, which is the useful pair to know: the
client is indifferent to chunking, so pick whatever the platform reports and
clamp it.

[`JadeTransport`]: https://docs.rs/jade-client-rs/latest/jade_client_rs/transport/trait.JadeTransport.html
