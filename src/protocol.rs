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

    /// Monotonic per-device frame counter.
    ///
    /// Carried in the signed preimage so a receiver can detect replay and reordering
    /// independently of the clock. Enforcement of monotonicity is not yet implemented.
    pub sequence: u64,

    /// Per-frame random nonce.
    ///
    /// Ensures two frames with identical content still produce distinct signatures and
    /// commitments, so the commitment cannot be used to confirm a guessed frame body.
    pub nonce: [u8; 16],

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
}

/// Decoded neural output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecodedOutput {
    /// 2D cursor position
    CursorPosition {
        /// Horizontal position, in screen pixels.
        x: f32,
        /// Vertical position, in screen pixels.
        y: f32,
    },

    /// Discrete command
    Command(String),

    /// Text/speech synthesis
    Text(String),

    /// Prosthetic control (joint angles)
    ProstheticControl {
        /// Target angle per joint, in radians, ordered as declared by the prosthesis.
        joints: Vec<f32>,
    },

    /// Vehicle control
    VehicleControl {
        /// Throttle demand, 0.0 (closed) to 1.0 (full).
        throttle: f32,
        /// Steering demand, -1.0 (full left) to 1.0 (full right).
        steering: f32,
        /// Brake demand, 0.0 (released) to 1.0 (full).
        brake: f32,
    },

    /// Raw classifier output
    Classification {
        /// Predicted class label.
        class: String,
        /// Model confidence in `class`, 0.0 to 1.0.
        confidence: f32,
    },
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

/// Domain-separation tag for the signature preimage.
///
/// Distinct tags keep the two preimages in disjoint namespaces: bytes built to be signed can
/// never be reinterpreted as bytes built to be committed, or vice versa.
const DOMAIN_SIGNATURE: &[u8] = b"NeuroGuard-v1-frame-signature";

/// Domain-separation tag for the commitment preimage.
const DOMAIN_COMMITMENT: &[u8] = b"NeuroGuard-v1-frame-commitment";

/// Builds an unambiguous byte encoding of a frame.
///
/// Every field is written as a 64-bit little-endian byte length followed by its contents. The
/// previous encoding concatenated fields raw, which is ambiguous whenever two adjacent fields
/// are variable-length: moving a byte from the end of `device_id.id` to the start of the next
/// field produced identical bytes, so one signature covered both readings. Length prefixes make
/// each field's extent explicit, so distinct frames always produce distinct preimages.
struct CanonicalWriter {
    buf: Vec<u8>,
}

impl CanonicalWriter {
    fn new(domain: &[u8]) -> Self {
        let mut writer = Self { buf: Vec::new() };
        writer.field(domain);
        writer
    }

    /// Write a length-prefixed byte string.
    fn field(&mut self, bytes: &[u8]) {
        self.buf
            .extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        self.buf.extend_from_slice(bytes);
    }

    fn u64(&mut self, value: u64) {
        self.field(&value.to_le_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.field(&value.to_le_bytes());
    }

    fn f32(&mut self, value: f32) {
        // Exact IEEE-754 bits, not a decimal rendering: the preimage must be reproducible
        // bit-for-bit on both sides of the link.
        self.field(&value.to_le_bytes());
    }

    /// Write a slice of samples as one length-prefixed run, avoiding a per-sample prefix and
    /// the intermediate copy a `field` call would need.
    fn samples(&mut self, samples: &[f32]) {
        let byte_len = std::mem::size_of_val(samples) as u64;
        self.buf.extend_from_slice(&byte_len.to_le_bytes());
        for sample in samples {
            self.buf.extend_from_slice(&sample.to_le_bytes());
        }
    }

    /// Write an optional hash with an explicit presence byte, so `None` and a zero hash are
    /// never the same bytes.
    fn optional_hash(&mut self, hash: Option<&[u8; 32]>) {
        match hash {
            Some(value) => {
                self.buf.push(1);
                self.field(value);
            }
            None => self.buf.push(0),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

impl DecodedOutput {
    /// Stable wire discriminant.
    ///
    /// Assigned explicitly rather than derived from declaration order, so reordering or
    /// inserting a variant cannot silently change what an existing signature covers.
    fn tag(&self) -> u8 {
        match self {
            DecodedOutput::CursorPosition { .. } => 1,
            DecodedOutput::Command(_) => 2,
            DecodedOutput::Text(_) => 3,
            DecodedOutput::ProstheticControl { .. } => 4,
            DecodedOutput::VehicleControl { .. } => 5,
            DecodedOutput::Classification { .. } => 6,
        }
    }

    fn write_canonical(&self, writer: &mut CanonicalWriter) {
        writer.field(&[self.tag()]);
        match self {
            DecodedOutput::CursorPosition { x, y } => {
                writer.f32(*x);
                writer.f32(*y);
            }
            DecodedOutput::Command(command) => writer.field(command.as_bytes()),
            DecodedOutput::Text(text) => writer.field(text.as_bytes()),
            DecodedOutput::ProstheticControl { joints } => writer.samples(joints),
            DecodedOutput::VehicleControl {
                throttle,
                steering,
                brake,
            } => {
                writer.f32(*throttle);
                writer.f32(*steering);
                writer.f32(*brake);
            }
            DecodedOutput::Classification { class, confidence } => {
                writer.field(class.as_bytes());
                writer.f32(*confidence);
            }
        }
    }
}

impl NeuralFrame {
    /// Write every authenticated field of the frame in a fixed order.
    ///
    /// The verifying key is not among them: it is no longer carried on the wire at all, but held
    /// by the registry and looked up by device id (NG-T001). Signing a key the sender chose would
    /// prove nothing, since an attacker who re-signs also swaps the key.
    fn write_body(&self, writer: &mut CanonicalWriter) {
        writer.field(self.device_id.id.as_bytes());
        writer.field(self.device_id.manufacturer.as_bytes());
        writer.field(self.device_id.model.as_bytes());
        writer.field(&self.firmware_hash);
        writer.i64(self.timestamp.timestamp_micros());
        writer.u64(self.sequence);
        writer.field(&self.nonce);
        writer.field(&self.transformation_hash);
        writer.field(&self.model_hash);
        writer.optional_hash(self.previous_commitment.as_ref());
        writer.samples(&self.signal_data);
        self.decoded_output.write_canonical(writer);
    }

    /// Compute the commitment hash for this frame (for hash chaining).
    ///
    /// Covers `decoded_output`, so a tampered command no longer occupies the same position in
    /// the provenance chain as the original.
    pub fn compute_commitment(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut writer = CanonicalWriter::new(DOMAIN_COMMITMENT);
        self.write_body(&mut writer);

        let mut hasher = Sha256::new();
        hasher.update(writer.into_bytes());
        hasher.finalize().into()
    }

    /// Get the data that should be signed by the device.
    ///
    /// Covers the decoded output and the full device identity, so the actuation command — a
    /// cursor position, prosthetic joint angles, a vehicle throttle demand — is authenticated
    /// rather than merely carried alongside authenticated data.
    pub fn signable_data(&self) -> Vec<u8> {
        let mut writer = CanonicalWriter::new(DOMAIN_SIGNATURE);
        self.write_body(&mut writer);
        writer.into_bytes()
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
            },
            firmware_hash: [1u8; 32],
            timestamp: Utc::now(),
            transformation_hash: [2u8; 32],
            model_hash: [3u8; 32],
            previous_commitment: None,
            sequence: 0,
            nonce: [4u8; 16],
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
