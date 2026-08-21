//! Neural signal protocol definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};

/// A neural signal frame with full provenance and attestation
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralFrame {
    /// Device attestation data
    pub device_id: DeviceId,

    /// Firmware hash (SHA-256)
    pub firmware_hash: [u8; 32],

    /// Frame timestamp
    pub timestamp: DateTime<Utc>,

    /// Signal transformation hash
    pub transformation_hash: [u8; 32],

    /// Decoder model hash
    pub model_hash: [u8; 32],

    /// Previous frame commitment (hash chain)
    pub previous_commitment: Option<[u8; 32]>,

    /// Raw neural signal data
    pub signal_data: Vec<f32>,

    /// Decoded output (e.g., cursor position, intended command)
    pub decoded_output: DecodedOutput,

    /// Device signature over the frame
    #[serde_as(as = "Bytes")]
    pub signature: [u8; 64],
}

/// Device identity and attestation information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceId {
    /// Unique device identifier
    pub id: String,

    /// Device manufacturer
    pub manufacturer: String,

    /// Device model
    pub model: String,

    /// Device public key (Ed25519)
    pub public_key: [u8; 32],
}

/// Decoded neural output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecodedOutput {
    /// 2D cursor position
    CursorPosition { x: f32, y: f32 },

    /// Discrete command
    Command(String),

    /// Text/speech synthesis
    Text(String),

    /// Prosthetic control (joint angles)
    ProstheticControl { joints: Vec<f32> },

    /// Vehicle control
    VehicleControl { throttle: f32, steering: f32, brake: f32 },

    /// Raw classifier output
    Classification { class: String, confidence: f32 },
}

/// Neural channel descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralChannel {
    /// Channel identifier
    pub id: u32,

    /// Channel type (motor cortex, sensory, etc.)
    pub channel_type: ChannelType,

    /// Sampling rate in Hz
    pub sample_rate: u32,

    /// Signal quality indicator (0.0 - 1.0)
    pub quality: f32,
}

/// Types of neural channels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChannelType {
    /// Motor cortex
    Motor,

    /// Sensory cortex
    Sensory,

    /// Visual cortex
    Visual,

    /// Auditory cortex
    Auditory,

    /// Other/unknown
    Other,
}

impl NeuralFrame {
    /// Compute the commitment hash for this frame (for hash chaining)
    pub fn compute_commitment(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&self.device_id.id.as_bytes());
        hasher.update(&self.firmware_hash);
        hasher.update(&self.timestamp.timestamp().to_le_bytes());
        hasher.update(&self.transformation_hash);
        hasher.update(&self.model_hash);

        if let Some(prev) = &self.previous_commitment {
            hasher.update(prev);
        }

        // Hash signal data
        for &sample in &self.signal_data {
            hasher.update(&sample.to_le_bytes());
        }

        hasher.finalize().into()
    }

    /// Get the data that should be signed by the device
    pub fn signable_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.device_id.id.as_bytes());
        data.extend_from_slice(&self.firmware_hash);
        data.extend_from_slice(&self.timestamp.timestamp().to_le_bytes());
        data.extend_from_slice(&self.transformation_hash);
        data.extend_from_slice(&self.model_hash);

        if let Some(prev) = &self.previous_commitment {
            data.extend_from_slice(prev);
        }

        for &sample in &self.signal_data {
            data.extend_from_slice(&sample.to_le_bytes());
        }

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_commitment() {
        let frame = NeuralFrame {
            device_id: DeviceId {
                id: "test-device".to_string(),
                manufacturer: "TestCo".to_string(),
                model: "V1".to_string(),
                public_key: [0u8; 32],
            },
            firmware_hash: [1u8; 32],
            timestamp: Utc::now(),
            transformation_hash: [2u8; 32],
            model_hash: [3u8; 32],
            previous_commitment: None,
            signal_data: vec![0.1, 0.2, 0.3],
            decoded_output: DecodedOutput::CursorPosition { x: 100.0, y: 200.0 },
            signature: [0u8; 64],
        };

        let commitment1 = frame.compute_commitment();
        let commitment2 = frame.compute_commitment();

        // Commitment should be deterministic
        assert_eq!(commitment1, commitment2);
    }
}
