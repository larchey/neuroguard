//! Error types for NeuroGuard

use thiserror::Error;

/// NeuroGuard result type
pub type Result<T> = std::result::Result<T, Error>;

/// NeuroGuard errors
#[derive(Error, Debug)]
pub enum Error {
    /// Device attestation failed
    #[error("device attestation failed: {0}")]
    AttestationFailed(String),

    /// Firmware hash mismatch
    #[error("firmware hash mismatch: expected {expected}, got {actual}")]
    FirmwareMismatch {
        /// Description of what the registry would have accepted.
        expected: String,
        /// Hex-encoded firmware hash actually presented.
        actual: String,
    },

    /// Decoder not approved
    #[error("decoder not approved: {0}")]
    DecoderRejected(String),

    /// Model hash invalid
    #[error("model hash invalid: {0}")]
    ModelHashInvalid(String),

    /// Signal provenance broken
    #[error("signal provenance broken: {0}")]
    ProvenanceBroken(String),

    /// Application not authorized
    #[error("application not authorized: {0}")]
    ApplicationUnauthorized(String),

    /// Policy violation
    #[error("policy violation: {0}")]
    PolicyViolation(String),

    /// Capability denied
    #[error("capability denied: {capability}")]
    CapabilityDenied {
        /// The capability that was requested but not held.
        capability: String,
    },

    /// Invalid frame
    #[error("invalid frame: {0}")]
    InvalidFrame(String),

    /// Signature verification failed
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Cryptographic error
    #[error("cryptographic error: {0}")]
    CryptoError(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}
