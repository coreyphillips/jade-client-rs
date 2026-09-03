//! A Rust client for the [Blockstream Jade](https://blockstream.com/jade/)
//! hardware wallet.
//!
//! Jade speaks a JSON-RPC shaped protocol encoded as CBOR, over either USB CDC
//! serial or Bluetooth. This crate implements that protocol, the blind
//! pinserver exchange that unlocks a PIN protected device, and PSBT signing.
//! Scope is Bitcoin single signature; Liquid, multisig and firmware updates are
//! not covered.
//!
//! # Getting started
//!
//! ```no_run
//! use jade_client_rs::{Jade, JadeNetwork, SerialTransport};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), jade_client_rs::JadeError> {
//! let device = jade_client_rs::serial::enumerate_devices()
//!     .into_iter()
//!     .next()
//!     .expect("no Jade attached");
//!
//! let transport = Arc::new(SerialTransport::open(&device.path)?);
//! let mut jade = Jade::connect(transport).await?;
//!
//! jade.unlock(JadeNetwork::Testnet).await?;
//!
//! let account = jade
//!     .get_xpub(JadeNetwork::Testnet, "m/84'/1'/0'")
//!     .await?;
//! println!("{} at {}", account.xpub, account.derivation_path);
//! # Ok(())
//! # }
//! ```
//!
//! # Transports
//!
//! [`JadeTransport`] is the seam every link goes through. A serial
//! implementation ships behind the `serial` feature. Bluetooth is deliberately
//! left to the caller, because BLE permissions, pairing and lifecycle belong to
//! the platform rather than to a protocol crate. To add one, implement
//! [`JadeTransport`] against the Nordic UART Service:
//!
//! | Role | UUID |
//! |---|---|
//! | Service | `6e400001-b5a3-f393-e0a9-e50e24dcca9e` |
//! | Write (host to Jade) | `6e400002-b5a3-f393-e0a9-e50e24dcca9e` |
//! | Notify (Jade to host) | `6e400003-b5a3-f393-e0a9-e50e24dcca9e` |
//!
//! Three rules matter, and each of them fails only against real hardware:
//!
//! 1. **Write with response.** Write-without-response silently drops chunks on
//!    the ESP32 GATT stack.
//! 2. **Do not pause between chunks of one request.** Firmware discards a
//!    partially received message after two seconds of silence, three on Jade v1.
//!    A 30 KB PSBT is roughly 60 writes, so a stall mid send breaks signing.
//! 3. **Clamp the chunk size** into `1..=`[`MAX_CHUNK_BYTES`]. For Bluetooth
//!    that means `min(negotiated_mtu - 3, 509)`.
//!
//! # Cancellation
//!
//! Jade has no cancel message, so the only way to stop a pending confirmation is
//! to close the link. [`Jade::cancel_handle`] returns a clonable handle that
//! works while an operation holds `&mut Jade`.
//!
//! # Features
//!
//! - `serial` (default): the [`SerialTransport`] and USB descriptor based
//!   discovery.
//! - `reqwest-pinserver` (default): a bundled HTTPS client for the pinserver
//!   exchange, with URL and resolved address hardening. The [`PinServerHttp`]
//!   trait is always available, so a caller can supply their own instead.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod client;
pub mod error;
pub mod path;
pub mod pinserver;
mod protocol;
pub mod transport;
pub mod types;

#[cfg(feature = "serial")]
pub mod serial;

#[cfg(test)]
mod tests;

pub use client::{Jade, MAX_PSBT_BYTES};
pub use error::{rpc_code, JadeError, JadeTransportErrorCode};
pub use pinserver::PinServerHttp;
pub use transport::{CancelHandle, JadeTransport, MAX_CHUNK_BYTES};
pub use types::{
    version_at_least, JadeAccount, JadeAccountExport, JadeAddressVariant, JadeDeviceInfo,
    JadeNetwork, JadePingStatus, JadeSignedMessage, JadeState, JadeTransportKind, JadeVersionInfo,
    JadeXpubResponse, MIN_JADE_FIRMWARE, MIN_JADE_FIRMWARE_TAPROOT,
};

#[cfg(feature = "reqwest-pinserver")]
pub use pinserver::ReqwestPinServer;

#[cfg(feature = "serial")]
pub use serial::SerialTransport;
