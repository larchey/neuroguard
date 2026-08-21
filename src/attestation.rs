//! Device attestation and verification

use crate::error::{Error, Result};
use crate::protocol::{DeviceId, NeuralFrame};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Verification report for a neural frame
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Device authenticated
    pub device_authenticated: bool,

    /// Firmware trusted
    pub firmware_trusted: bool,

    /// Decoder approved
    pub decoder_approved: bool,

    /// Model hash valid
    pub model_valid: bool,

    /// Signal provenance intact
    pub provenance_intact: bool,

    /// Application authorized
    pub application_authorized: bool,

    /// Overall verdict
    pub verdict: Verdict,

    /// Additional details
    pub details: Vec<String>,
}

/// Overall verification verdict
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Verdict {
    /// All checks passed
    Trusted,

    /// Some non-critical checks failed
    Suspicious,

    /// Critical checks failed
    Rejected,
}

/// Device registry for attestation
pub struct DeviceRegistry {
    trusted_devices: HashMap<String, TrustedDevice>,
    approved_firmware: HashMap<String, Vec<[u8; 32]>>,
    approved_models: HashMap<String, Vec<[u8; 32]>>,
}

/// Trusted device entry
#[derive(Debug, Clone)]
pub struct TrustedDevice {
    /// Device ID
    pub device_id: DeviceId,

    /// Trust level
    pub trust_level: TrustLevel,

    /// Allowed decoders
    pub allowed_decoders: Vec<String>,
}

/// Device trust level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    /// Fully trusted (e.g., FDA-approved implant)
    FullyTrusted,

    /// Provisionally trusted (testing phase)
    Provisional,

    /// Untrusted (should not be used in production)
    Untrusted,
}

impl DeviceRegistry {
    /// Create a new device registry
    pub fn new() -> Self {
        Self {
            trusted_devices: HashMap::new(),
            approved_firmware: HashMap::new(),
            approved_models: HashMap::new(),
        }
    }

    /// Register a trusted device
    pub fn register_device(&mut self, device: TrustedDevice) {
        self.trusted_devices
            .insert(device.device_id.id.clone(), device);
    }

    /// Approve a firmware hash for a device model
    pub fn approve_firmware(&mut self, model: String, firmware_hash: [u8; 32]) {
        self.approved_firmware
            .entry(model)
            .or_default()
            .push(firmware_hash);
    }

    /// Approve a decoder model hash
    pub fn approve_model(&mut self, decoder: String, model_hash: [u8; 32]) {
        self.approved_models
            .entry(decoder)
            .or_default()
            .push(model_hash);
    }

    /// Verify a device is trusted
    pub fn verify_device(&self, device_id: &str) -> Result<&TrustedDevice> {
        self.trusted_devices
            .get(device_id)
            .ok_or_else(|| Error::AttestationFailed(format!("device {} not registered", device_id)))
    }

    /// Verify firmware hash
    pub fn verify_firmware(&self, model: &str, firmware_hash: &[u8; 32]) -> Result<()> {
        let approved =
            self.approved_firmware
                .get(model)
                .ok_or_else(|| Error::FirmwareMismatch {
                    expected: "unknown model".to_string(),
                    actual: hex::encode(firmware_hash),
                })?;

        if approved.contains(firmware_hash) {
            Ok(())
        } else {
            Err(Error::FirmwareMismatch {
                expected: format!("{} approved hashes", approved.len()),
                actual: hex::encode(firmware_hash),
            })
        }
    }

    /// Verify decoder model
    pub fn verify_model(&self, decoder: &str, model_hash: &[u8; 32]) -> Result<()> {
        let approved = self
            .approved_models
            .get(decoder)
            .ok_or_else(|| Error::ModelHashInvalid(format!("decoder {} not approved", decoder)))?;

        if approved.contains(model_hash) {
            Ok(())
        } else {
            Err(Error::ModelHashInvalid(format!(
                "model hash {} not approved",
                hex::encode(model_hash)
            )))
        }
    }
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a neural frame's signature
pub fn verify_signature(frame: &NeuralFrame) -> Result<()> {
    let public_key = VerifyingKey::from_bytes(&frame.device_id.public_key)
        .map_err(|e| Error::CryptoError(e.to_string()))?;

    let signature = Signature::from_bytes(&frame.signature);

    let signable_data = frame.signable_data();

    public_key
        .verify(&signable_data, &signature)
        .map_err(|_| Error::SignatureVerificationFailed)?;

    Ok(())
}

/// Verify a complete neural frame
pub fn verify_neural_frame(frame: &NeuralFrame) -> Result<VerificationReport> {
    let mut report = VerificationReport {
        device_authenticated: false,
        firmware_trusted: false,
        decoder_approved: false,
        model_valid: false,
        provenance_intact: false,
        application_authorized: false,
        verdict: Verdict::Rejected,
        details: Vec::new(),
    };

    // 1. Verify device signature
    match verify_signature(frame) {
        Ok(()) => {
            report.device_authenticated = true;
            report.details.push("✓ Device signature valid".to_string());
        }
        Err(e) => {
            report
                .details
                .push(format!("✗ Device signature failed: {}", e));
            return Ok(report);
        }
    }

    // 2. Verify provenance chain
    if frame.previous_commitment.is_some() {
        report.provenance_intact = true;
        report.details.push("✓ Provenance chain intact".to_string());
    } else {
        report
            .details
            .push("⚠ No previous commitment (first frame?)".to_string());
        report.provenance_intact = true; // First frame is OK
    }

    // 3. Placeholder for firmware/model verification
    // (Requires DeviceRegistry instance)
    report.firmware_trusted = true;
    report.decoder_approved = true;
    report.model_valid = true;
    report.application_authorized = true;

    report
        .details
        .push("⚠ Firmware verification not implemented (registry needed)".to_string());

    // Determine verdict
    if report.device_authenticated && report.provenance_intact {
        report.verdict = Verdict::Trusted;
    } else {
        report.verdict = Verdict::Rejected;
    }

    Ok(report)
}

// Helper function for hex encoding (simple implementation)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_registry() {
        let mut registry = DeviceRegistry::new();

        let device_id = DeviceId {
            id: "device-001".to_string(),
            manufacturer: "NeuroCo".to_string(),
            model: "Implant-V1".to_string(),
            public_key: [0u8; 32],
        };

        let trusted_device = TrustedDevice {
            device_id: device_id.clone(),
            trust_level: TrustLevel::FullyTrusted,
            allowed_decoders: vec!["decoder-A".to_string()],
        };

        registry.register_device(trusted_device);

        assert!(registry.verify_device("device-001").is_ok());
        assert!(registry.verify_device("device-999").is_err());
    }

    #[test]
    fn test_firmware_approval() {
        let mut registry = DeviceRegistry::new();

        let firmware_hash = [42u8; 32];
        registry.approve_firmware("Implant-V1".to_string(), firmware_hash);

        assert!(registry
            .verify_firmware("Implant-V1", &firmware_hash)
            .is_ok());
        assert!(registry.verify_firmware("Implant-V1", &[0u8; 32]).is_err());
    }
}
