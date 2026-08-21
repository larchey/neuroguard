//! Neural signal provenance and chain of custody

use crate::error::{Error, Result};
use crate::protocol::NeuralFrame;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Provenance chain tracker
pub struct ProvenanceChain {
    /// Chain of frame commitments
    chain: Vec<ChainLink>,

    /// Index for fast lookup
    commitment_index: HashMap<[u8; 32], usize>,
}

/// A single link in the provenance chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainLink {
    /// Frame commitment hash
    pub commitment: [u8; 32],

    /// Previous commitment (None for genesis)
    pub previous: Option<[u8; 32]>,

    /// Transformation applied
    pub transformation: Transformation,

    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Device that produced this link
    pub device_id: String,
}

/// Neural signal transformation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transformation {
    /// Transformation type
    pub transform_type: TransformType,

    /// Hash of the transformation function/model
    pub transform_hash: [u8; 32],

    /// Parameters used
    pub parameters: HashMap<String, String>,
}

/// Types of transformations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransformType {
    /// Raw signal acquisition
    Acquisition,

    /// Noise filtering
    Filtering,

    /// Feature extraction
    FeatureExtraction,

    /// Neural decoding
    Decoding,

    /// Post-processing
    PostProcessing,

    /// Calibration
    Calibration,
}

impl ProvenanceChain {
    /// Create a new provenance chain
    pub fn new() -> Self {
        Self {
            chain: Vec::new(),
            commitment_index: HashMap::new(),
        }
    }

    /// Add a frame to the provenance chain
    pub fn add_frame(&mut self, frame: &NeuralFrame) -> Result<()> {
        let commitment = frame.compute_commitment();

        // Verify chain integrity
        if let Some(prev_commitment) = &frame.previous_commitment {
            if !self.commitment_index.contains_key(prev_commitment) {
                return Err(Error::ProvenanceBroken(
                    "previous commitment not found in chain".to_string(),
                ));
            }
        } else if !self.chain.is_empty() {
            return Err(Error::ProvenanceBroken(
                "missing previous commitment".to_string(),
            ));
        }

        let link = ChainLink {
            commitment,
            previous: frame.previous_commitment,
            transformation: Transformation {
                transform_type: TransformType::Decoding,
                transform_hash: frame.transformation_hash,
                parameters: HashMap::new(),
            },
            timestamp: frame.timestamp,
            device_id: frame.device_id.id.clone(),
        };

        let index = self.chain.len();
        self.chain.push(link);
        self.commitment_index.insert(commitment, index);

        Ok(())
    }

    /// Verify the entire chain's integrity
    pub fn verify_chain(&self) -> Result<()> {
        if self.chain.is_empty() {
            return Ok(());
        }

        // Genesis block should have no previous commitment
        if self.chain[0].previous.is_some() {
            return Err(Error::ProvenanceBroken(
                "genesis block has previous commitment".to_string(),
            ));
        }

        // Verify each subsequent link
        for i in 1..self.chain.len() {
            let current = &self.chain[i];
            let prev_commitment = current.previous.ok_or_else(|| {
                Error::ProvenanceBroken(format!("link {} missing previous commitment", i))
            })?;

            let prev_link = &self.chain[i - 1];
            if prev_link.commitment != prev_commitment {
                return Err(Error::ProvenanceBroken(format!(
                    "link {} previous commitment mismatch",
                    i
                )));
            }
        }

        Ok(())
    }

    /// Get the full history for a frame
    pub fn get_history(&self, commitment: &[u8; 32]) -> Result<Vec<&ChainLink>> {
        let mut history = Vec::new();

        let mut current_idx = *self
            .commitment_index
            .get(commitment)
            .ok_or_else(|| Error::ProvenanceBroken("commitment not found".to_string()))?;

        loop {
            let link = &self.chain[current_idx];
            history.push(link);

            if let Some(prev) = &link.previous {
                current_idx = *self
                    .commitment_index
                    .get(prev)
                    .ok_or_else(|| Error::ProvenanceBroken("broken chain link".to_string()))?;
            } else {
                break;
            }
        }

        history.reverse();
        Ok(history)
    }

    /// Get chain length
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Check if chain is empty
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }
}

impl Default for ProvenanceChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a transformation hash
pub fn compute_transformation_hash(
    transform_type: &TransformType,
    code: &[u8],
    parameters: &HashMap<String, String>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Hash the transformation type
    hasher.update(format!("{:?}", transform_type).as_bytes());

    // Hash the code/model
    hasher.update(code);

    // Hash parameters (sorted for determinism)
    let mut param_keys: Vec<_> = parameters.keys().collect();
    param_keys.sort();

    for key in param_keys {
        hasher.update(key.as_bytes());
        hasher.update(parameters[key].as_bytes());
    }

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{DecodedOutput, DeviceId};
    use chrono::Utc;

    #[test]
    fn test_provenance_chain() {
        let mut chain = ProvenanceChain::new();

        let device_id = DeviceId {
            id: "device-001".to_string(),
            manufacturer: "NeuroCo".to_string(),
            model: "V1".to_string(),
            public_key: [0u8; 32],
        };

        // Genesis frame
        let mut frame1 = NeuralFrame {
            device_id: device_id.clone(),
            firmware_hash: [1u8; 32],
            timestamp: Utc::now(),
            transformation_hash: [2u8; 32],
            model_hash: [3u8; 32],
            previous_commitment: None,
            signal_data: vec![0.1],
            decoded_output: DecodedOutput::CursorPosition { x: 0.0, y: 0.0 },
            signature: [0u8; 64],
        };

        chain.add_frame(&frame1).unwrap();

        // Second frame
        let commitment1 = frame1.compute_commitment();
        frame1.previous_commitment = Some(commitment1);
        frame1.signal_data = vec![0.2];

        chain.add_frame(&frame1).unwrap();

        assert_eq!(chain.len(), 2);
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn test_transformation_hash() {
        let params = HashMap::from([("alpha".to_string(), "0.5".to_string())]);

        let hash1 = compute_transformation_hash(&TransformType::Decoding, b"model_v1", &params);
        let hash2 = compute_transformation_hash(&TransformType::Decoding, b"model_v1", &params);

        assert_eq!(hash1, hash2); // Deterministic

        let hash3 = compute_transformation_hash(&TransformType::Decoding, b"model_v2", &params);
        assert_ne!(hash1, hash3); // Different code = different hash
    }
}
