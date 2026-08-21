//! NeuroGuard: Security Middleware for Brain-Computer Interfaces
//!
//! NeuroGuard provides cryptographic attestation, provenance tracking, and policy
//! enforcement for neural interfaces. Includes a virtual BCI device for security testing.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod attestation;
pub mod error;
pub mod policy;
pub mod protocol;
pub mod provenance;
pub mod virtual_bci;

pub use error::{Error, Result};

/// Core NeuroGuard version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Verify a complete neural frame through the security pipeline
///
/// The registry supplies the device's enrolled verifying key and its approved firmware and model
/// hashes; verification is meaningless without it.
///
/// # Security Properties
/// - Device authentication
/// - Firmware integrity
/// - Decoder approval
/// - Model hash validation
/// - Signal provenance
/// - Application authorization
pub fn verify_frame(
    frame: &protocol::NeuralFrame,
    registry: &attestation::DeviceRegistry,
) -> Result<attestation::VerificationReport> {
    attestation::verify_neural_frame(frame, registry)
}
