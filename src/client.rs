//! The device session.
//!
//! [`Jade`] owns one connection and takes `&mut self` for every operation, so
//! the "one request at a time" rule Jade's firmware enforces is a compile time
//! property rather than a runtime lock. A host that needs shared access wraps it
//! in whatever lock it already uses.
//!
//! Aborting is the exception: [`Jade::cancel_handle`] hands out a clonable
//! handle that still works while an operation holds `&mut self`, which is what a
//! cancel button on a signing screen needs.

use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::bip32::{DerivationPath, Xpub};
use bitcoin::psbt::Psbt;
use rand::RngCore;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::JadeError;
use crate::path;
use crate::pinserver::{self, PinServerHttp};
use crate::protocol::{result_bool, result_text};
use crate::transport::{CancelHandle, JadeConnection, JadeTransport};
use crate::types::*;

/// Timeout for calls the device answers on its own.
const QUICK_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for calls that wait on a physical button press.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(300);

/// Largest PSBT this crate will send.
///
/// Jade's input buffer is 17 KiB without SPIRAM, and composed PSBTs carry full
/// previous transactions, so this is worth checking before a long transfer the
/// device would reject at the end.
pub const MAX_PSBT_BYTES: u64 = 16 * 1024;

/// An open session with a Jade device.
pub struct Jade {
    connection: JadeConnection,
    version: JadeVersionInfo,
    unlocked_network: Option<JadeNetwork>,
}

impl std::fmt::Debug for Jade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jade")
            .field("version", &self.version.jade_version)
            .field("state", &self.version.jade_state)
            .field("unlocked_network", &self.unlocked_network)
            .finish_non_exhaustive()
    }
}

impl Jade {
    /// Open a device over `transport`.
    ///
    /// Reads the version summary and contributes 32 bytes of host entropy to the
    /// device's pool. [`Jade::version_info`] then says what to do next:
    /// [`JadeState::Locked`] means call [`Jade::unlock_with`],
    /// [`JadeState::Ready`] means the device is already usable, and
    /// [`JadeState::Uninit`] means the user has to create or restore a wallet on
    /// the device itself, which cannot be driven from here.
    pub async fn connect(transport: Arc<dyn JadeTransport>) -> Result<Self, JadeError> {
        let aborted = Arc::new(AtomicBool::new(false));
        let mut connection = JadeConnection::new(transport, aborted);

        let version = Self::read_version(&mut connection).await?;
        Self::add_entropy(&mut connection).await?;

        Ok(Self {
            connection,
            version,
            unlocked_network: None,
        })
    }

    /// The version summary, as of the last read.
    pub fn version_info(&self) -> &JadeVersionInfo {
        &self.version
    }

    /// The network the device was unlocked for, if it has been unlocked.
    pub fn unlocked_network(&self) -> Option<JadeNetwork> {
        self.unlocked_network
    }

    /// A handle that can abort an operation from another task.
    pub fn cancel_handle(&self) -> CancelHandle {
        self.connection.cancel_handle()
    }

    /// Close the link.
    pub async fn close(self) -> Result<(), JadeError> {
        self.connection.transport().close().await
    }

    async fn read_version(connection: &mut JadeConnection) -> Result<JadeVersionInfo, JadeError> {
        let reply = connection
            .exchange("get_version_info", Option::<()>::None, QUICK_TIMEOUT)
            .await?;
        let value = reply.into_result(MIN_JADE_FIRMWARE)?;
        let wire: WireVersionInfo = value.deserialized().map_err(|error| {
            JadeError::protocol(format!("unexpected get_version_info reply: {error}"))
        })?;
        Ok(JadeVersionInfo::from(wire))
    }

    async fn add_entropy(connection: &mut JadeConnection) -> Result<(), JadeError> {
        #[derive(Serialize)]
        struct AddEntropyParams {
            #[serde(with = "serde_bytes")]
            entropy: Vec<u8>,
        }

        let mut entropy = Zeroizing::new(vec![0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        let params = AddEntropyParams {
            entropy: entropy.to_vec(),
        };
        let reply = connection
            .exchange("add_entropy", Some(params), QUICK_TIMEOUT)
            .await?;
        result_bool(&reply.into_result(MIN_JADE_FIRMWARE)?)?;
        Ok(())
    }

    /// Re-read the version summary from the device.
    pub async fn refresh_version_info(&mut self) -> Result<&JadeVersionInfo, JadeError> {
        self.version = Self::read_version(&mut self.connection).await?;
        Ok(&self.version)
    }

    /// Whether the device is idle, busy, or waiting on the user.
    pub async fn ping(&mut self) -> Result<JadePingStatus, JadeError> {
        let reply = self
            .connection
            .exchange("ping", Option::<()>::None, QUICK_TIMEOUT)
            .await?;
        let value = reply.into_result(MIN_JADE_FIRMWARE)?;
        let raw = value
            .as_integer()
            .and_then(|integer| u64::try_from(integer).ok())
            .ok_or_else(|| JadeError::protocol("expected an integer ping result"))?;
        Ok(JadePingStatus::from_wire(raw))
    }

    /// Unlock the device using the bundled pinserver client.
    #[cfg(feature = "reqwest-pinserver")]
    pub async fn unlock(&mut self, network: JadeNetwork) -> Result<(), JadeError> {
        self.unlock_with(network, &crate::pinserver::ReqwestPinServer)
            .await
    }

    /// Unlock the device, performing the pinserver exchange through `http`.
    ///
    /// The exchange is end to end encrypted between the device and the
    /// pinserver, so the PIN never reaches the host; its role is to carry bytes.
    /// The PIN itself is entered on the device.
    pub async fn unlock_with(
        &mut self,
        network: JadeNetwork,
        http: &dyn PinServerHttp,
    ) -> Result<(), JadeError> {
        // A device with no wallet starts an on-device setup flow that can take
        // minutes and cannot be driven from here.
        if self.version.jade_state == JadeState::Uninit {
            return Err(JadeError::DeviceUninitialized);
        }

        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);

        pinserver::run_unlock(&mut self.connection, network, http, epoch).await?;
        self.unlocked_network = Some(network);

        // The cached state still reads LOCKED until this is refreshed, and the
        // point of exposing it is telling the caller whether to prompt.
        let _ = self.refresh_version_info().await;
        Ok(())
    }

    /// Lock the device and zero its in-memory key material.
    pub async fn logout(&mut self) -> Result<(), JadeError> {
        let reply = self
            .connection
            .exchange("logout", Option::<()>::None, QUICK_TIMEOUT)
            .await?;
        result_bool(&reply.into_result(MIN_JADE_FIRMWARE)?)?;
        self.unlocked_network = None;
        let _ = self.refresh_version_info().await;
        Ok(())
    }

    /// Check a requested network against the one that was unlocked.
    fn check_network(&self, network: JadeNetwork) -> Result<(), JadeError> {
        match self.unlocked_network {
            Some(unlocked) if unlocked != network => Err(JadeError::NetworkMismatch {
                error_details: format!(
                    "the device was unlocked for {} but the request is for {}",
                    unlocked.wire_name(),
                    network.wire_name()
                ),
            }),
            _ => Ok(()),
        }
    }

    async fn raw_xpub(
        &mut self,
        network: JadeNetwork,
        derivation_path: &str,
        allow_master: bool,
    ) -> Result<String, JadeError> {
        #[derive(Serialize)]
        struct GetXpubParams<'a> {
            network: &'a str,
            path: Vec<u32>,
        }

        let wire_path = path::to_wire(derivation_path, allow_master)?;
        let params = GetXpubParams {
            network: network.wire_name(),
            path: wire_path,
        };
        let reply = self
            .connection
            .exchange("get_xpub", Some(params), QUICK_TIMEOUT)
            .await?;
        result_text(&reply.into_result(MIN_JADE_FIRMWARE)?)
    }

    /// The device's master fingerprint, eight lowercase hex characters.
    ///
    /// Taken from the parent fingerprint of `m/0'` rather than by requesting the
    /// master xpub directly, which is how HWI does it and which avoids relying
    /// on the device accepting an empty path.
    pub async fn master_fingerprint(&mut self, network: JadeNetwork) -> Result<String, JadeError> {
        self.check_network(network)?;
        let xpub = self.raw_xpub(network, "m/0'", false).await?;
        let parsed = Xpub::from_str(&xpub).map_err(|error| {
            JadeError::protocol(format!("device returned an unparsable xpub: {error}"))
        })?;
        Ok(format!("{:08x}", parsed.parent_fingerprint))
    }

    /// Fetch an extended public key, echoed back with the request it answers.
    pub async fn get_xpub(
        &mut self,
        network: JadeNetwork,
        derivation_path: &str,
    ) -> Result<JadeXpubResponse, JadeError> {
        self.check_network(network)?;
        let fingerprint = self.master_fingerprint(network).await?;
        let xpub = self.raw_xpub(network, derivation_path, false).await?;
        verify_xpub(&xpub, derivation_path)?;

        Ok(JadeXpubResponse {
            xpub,
            derivation_path: derivation_path.to_string(),
            master_fingerprint: fingerprint,
        })
    }

    /// Fetch the account keys an import needs, in one pass over the link.
    ///
    /// Each key costs a round trip, which is slow over Bluetooth, so batching
    /// them here keeps the caller from reacquiring the device between each one.
    /// No user confirmation is involved.
    pub async fn account_export(
        &mut self,
        network: JadeNetwork,
        account_index: u32,
        variants: &[JadeAddressVariant],
    ) -> Result<JadeAccountExport, JadeError> {
        self.check_network(network)?;
        let fingerprint = self.master_fingerprint(network).await?;

        let mut accounts = Vec::with_capacity(variants.len());
        for variant in variants {
            let derivation_path = format!(
                "m/{}'/{}'/{account_index}'",
                variant.purpose(),
                network.coin_type()
            );
            let xpub = self.raw_xpub(network, &derivation_path, false).await?;
            verify_xpub(&xpub, &derivation_path)?;
            accounts.push(JadeAccount {
                variant: *variant,
                xpub,
                derivation_path,
            });
        }

        Ok(JadeAccountExport {
            master_fingerprint: fingerprint,
            account_index,
            accounts,
        })
    }

    /// Display an address on the device and check it against `expected_address`.
    ///
    /// Jade always prompts on screen for this call, so it is a verification step
    /// rather than a way to fetch an address: the caller already knows the
    /// address from the account xpub. Comparing the two catches corruption and
    /// firmware bugs. A wholly malicious device is still caught by the user
    /// reading the device screen.
    pub async fn verify_address(
        &mut self,
        network: JadeNetwork,
        variant: JadeAddressVariant,
        derivation_path: &str,
        expected_address: &str,
    ) -> Result<(), JadeError> {
        #[derive(Serialize)]
        struct GetReceiveAddressParams<'a> {
            network: &'a str,
            variant: &'a str,
            path: Vec<u32>,
        }

        self.check_network(network)?;

        // Taproot addresses arrived in 1.0.34. Older firmware answers with a
        // generic parameter error, which says nothing useful.
        if variant == JadeAddressVariant::Tr
            && !version_at_least(&self.version.jade_version, MIN_JADE_FIRMWARE_TAPROOT)
        {
            return Err(JadeError::UnsupportedFirmware {
                installed: self.version.jade_version.clone(),
                required: MIN_JADE_FIRMWARE_TAPROOT.to_string(),
            });
        }

        // A legacy variant under an m/84' path is a caller bug worth catching
        // before the device displays something misleading.
        if let Some(purpose) = path::purpose(derivation_path) {
            if purpose != variant.purpose() {
                return Err(JadeError::InvalidPath {
                    error_details: format!(
                        "path purpose {purpose} does not match the {} variant",
                        variant.wire_name()
                    ),
                });
            }
        }

        let request = GetReceiveAddressParams {
            network: network.wire_name(),
            variant: variant.wire_name(),
            path: path::to_wire(derivation_path, false)?,
        };
        let reply = self
            .connection
            .exchange("get_receive_address", Some(request), CONFIRM_TIMEOUT)
            .await?;
        let returned = result_text(&reply.into_result(MIN_JADE_FIRMWARE)?)?;

        if returned != expected_address {
            return Err(JadeError::AddressMismatch {
                expected: expected_address.to_string(),
                returned,
            });
        }
        Ok(())
    }

    /// Sign a message, returning the signature with the address that verifies it.
    pub async fn sign_message(
        &mut self,
        network: JadeNetwork,
        derivation_path: &str,
        message: &str,
    ) -> Result<JadeSignedMessage, JadeError> {
        #[derive(Serialize)]
        struct SignMessageParams<'a> {
            message: &'a str,
            path: Vec<u32>,
        }

        self.check_network(network)?;
        let wire_path = path::to_wire(derivation_path, false)?;

        // Derive the address here so the caller can verify without a second
        // round trip to the device.
        let xpub = self.raw_xpub(network, derivation_path, false).await?;
        let parsed = Xpub::from_str(&xpub).map_err(|error| {
            JadeError::protocol(format!("device returned an unparsable xpub: {error}"))
        })?;
        let address = bitcoin::Address::p2wpkh(
            &bitcoin::CompressedPublicKey(parsed.public_key),
            bitcoin::Network::from(network),
        )
        .to_string();

        let request = SignMessageParams {
            message,
            path: wire_path,
        };
        let reply = self
            .connection
            .exchange("sign_message", Some(request), CONFIRM_TIMEOUT)
            .await?;
        let signature = result_text(&reply.into_result(MIN_JADE_FIRMWARE)?)?;

        Ok(JadeSignedMessage {
            signature,
            address,
            derivation_path: derivation_path.to_string(),
        })
    }

    /// Sign a PSBT.
    ///
    /// The reply is checked against what was sent before it is returned: same
    /// unsigned transaction, same input and output counts, unchanged previous
    /// output metadata, and at least one new signature.
    ///
    /// Before the round trip, a PSBT is rejected if it exceeds the device's
    /// input buffer, requests an unsupported sighash type, or carries no BIP32
    /// origin for this device's master fingerprint. That last case is the most
    /// common integration failure: without key origins the device signs nothing
    /// and the problem only surfaces as a finalization error much later.
    pub async fn sign_psbt(
        &mut self,
        network: JadeNetwork,
        psbt: &Psbt,
    ) -> Result<Psbt, JadeError> {
        #[derive(Serialize)]
        struct SignPsbtParams<'a> {
            network: &'a str,
            #[serde(with = "serde_bytes")]
            psbt: Vec<u8>,
        }

        self.check_network(network)?;

        let bytes = psbt.serialize();
        if bytes.len() as u64 > MAX_PSBT_BYTES {
            return Err(JadeError::PsbtTooLarge {
                size: bytes.len() as u64,
                max: MAX_PSBT_BYTES,
            });
        }
        self.check_signable(psbt, network).await?;

        let request = SignPsbtParams {
            network: network.wire_name(),
            psbt: bytes,
        };
        let signed_bytes = self
            .connection
            .exchange_reassembled("sign_psbt", Some(request), CONFIRM_TIMEOUT)
            .await?;

        let signed = Psbt::deserialize(&signed_bytes).map_err(|error| JadeError::InvalidPsbt {
            error_details: format!("device returned an unparsable PSBT: {error}"),
        })?;
        verify_signed_psbt(psbt, &signed)?;
        Ok(signed)
    }

    /// Reject a PSBT the device would refuse or silently not sign.
    async fn check_signable(&mut self, psbt: &Psbt, network: JadeNetwork) -> Result<(), JadeError> {
        for (index, input) in psbt.inputs.iter().enumerate() {
            if let Some(sighash) = input.sighash_type {
                let is_all = sighash
                    .ecdsa_hash_ty()
                    .map(|ty| ty == bitcoin::sighash::EcdsaSighashType::All)
                    .unwrap_or(false);
                let is_default = sighash
                    .taproot_hash_ty()
                    .map(|ty| ty == bitcoin::sighash::TapSighashType::Default)
                    .unwrap_or(false);
                if !is_all && !is_default {
                    return Err(JadeError::InvalidPsbt {
                        error_details: format!(
                            "input {index} requests an unsupported sighash type"
                        ),
                    });
                }
            }
        }

        let Ok(device_fingerprint) = self.master_fingerprint(network).await else {
            return Ok(());
        };
        let mut seen = Vec::new();
        let mut matched = false;
        for input in &psbt.inputs {
            for (fingerprint, _) in input.bip32_derivation.values() {
                let rendered = format!("{fingerprint:08x}");
                matched |= rendered == device_fingerprint;
                seen.push(rendered);
            }
            for (_, (fingerprint, _)) in input.tap_key_origins.values() {
                let rendered = format!("{fingerprint:08x}");
                matched |= rendered == device_fingerprint;
                seen.push(rendered);
            }
        }
        if !seen.is_empty() && !matched {
            seen.sort();
            seen.dedup();
            return Err(JadeError::FingerprintMismatch {
                device: device_fingerprint,
                psbt: seen.join(", "),
            });
        }
        Ok(())
    }
}

/// Confirm the device answered the question that was asked.
fn verify_xpub(xpub: &str, derivation_path: &str) -> Result<(), JadeError> {
    let parsed = Xpub::from_str(xpub).map_err(|error| {
        JadeError::protocol(format!("device returned an unparsable xpub: {error}"))
    })?;
    let expected = DerivationPath::from_str(derivation_path.trim()).map_err(|error| {
        JadeError::InvalidPath {
            error_details: error.to_string(),
        }
    })?;
    let depth = expected.len();
    if usize::from(parsed.depth) != depth {
        return Err(JadeError::protocol(format!(
            "device returned a key at depth {} for a path of depth {depth}",
            parsed.depth
        )));
    }
    Ok(())
}

/// Check what came back against what was sent.
pub(crate) fn verify_signed_psbt(sent: &Psbt, signed: &Psbt) -> Result<(), JadeError> {
    if sent.unsigned_tx != signed.unsigned_tx {
        return Err(JadeError::InvalidPsbt {
            error_details: "device returned a different unsigned transaction".to_string(),
        });
    }
    if sent.inputs.len() != signed.inputs.len() || sent.outputs.len() != signed.outputs.len() {
        return Err(JadeError::InvalidPsbt {
            error_details: "device changed the number of inputs or outputs".to_string(),
        });
    }

    for (index, (before, after)) in sent.inputs.iter().zip(signed.inputs.iter()).enumerate() {
        if before.witness_utxo != after.witness_utxo {
            return Err(JadeError::InvalidPsbt {
                error_details: format!("device altered the witness UTXO of input {index}"),
            });
        }
        if before.non_witness_utxo != after.non_witness_utxo {
            return Err(JadeError::InvalidPsbt {
                error_details: format!("device altered the previous transaction of input {index}"),
            });
        }
    }

    let gained_signature = signed.inputs.iter().enumerate().any(|(index, input)| {
        let before = &sent.inputs[index];
        input.partial_sigs.len() > before.partial_sigs.len()
            || (input.final_script_witness.is_some() && before.final_script_witness.is_none())
            || (input.final_script_sig.is_some() && before.final_script_sig.is_none())
            || (input.tap_key_sig.is_some() && before.tap_key_sig.is_none())
    });
    if !gained_signature {
        return Err(JadeError::NothingSigned);
    }
    Ok(())
}
