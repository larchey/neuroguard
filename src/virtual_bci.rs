//! Virtual BCI device simulator for security testing

use crate::error::Result;
use crate::protocol::{ChannelType, DecodedOutput, DeviceId, NeuralChannel, NeuralFrame};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand::Rng;
use sha2::{Digest, Sha256};

/// Virtual BCI device for testing
pub struct VirtualBCI {
    /// Device identity
    device_id: DeviceId,

    /// Signing key for attestation
    signing_key: SigningKey,

    /// Current firmware hash
    firmware_hash: [u8; 32],

    /// Current model hash
    model_hash: [u8; 32],

    /// Previous frame commitment (for chain)
    previous_commitment: Option<[u8; 32]>,

    /// Monotonic frame counter, emitted in each frame's signed preimage
    sequence: u64,

    /// Available neural channels
    channels: Vec<NeuralChannel>,

    /// Device mode
    mode: DeviceMode,
}

/// Device operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMode {
    /// Normal operation
    Normal,

    /// Simulating specific attack scenario
    AttackSimulation(AttackType),

    /// Offline/disconnected
    Offline,
}

/// Types of attacks the virtual BCI can simulate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackType {
    /// Replay old neural commands
    ReplayAttack,

    /// Inject malicious signals
    SignalInjection,

    /// Use compromised decoder model
    MaliciousDecoder,

    /// Firmware downgrade attack
    FirmwareDowngrade,

    /// Device impersonation
    DeviceImpersonation,

    /// Tampered calibration data
    TamperedCalibration,

    /// Command modification
    CommandModification,

    /// Signal exfiltration attempt
    DataExfiltration,
}

impl VirtualBCI {
    /// Create a new virtual BCI device
    pub fn new(device_id: String, manufacturer: String, model: String) -> Self {
        let mut rng = rand::thread_rng();

        // Generate random 32-byte secret key
        let mut secret_bytes = [0u8; 32];
        for byte in &mut secret_bytes {
            *byte = rng.gen();
        }

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();

        let device_id = DeviceId {
            id: device_id,
            manufacturer,
            model,
            public_key,
        };

        // Generate default hashes
        let firmware_hash = Self::compute_firmware_hash(b"firmware-v1.0.0");
        let model_hash = Self::compute_model_hash(b"decoder-model-v1");

        // Create default neural channels
        let channels = vec![
            NeuralChannel {
                id: 1,
                channel_type: ChannelType::Motor,
                sample_rate: 1000,
                quality: 0.95,
            },
            NeuralChannel {
                id: 2,
                channel_type: ChannelType::Motor,
                sample_rate: 1000,
                quality: 0.92,
            },
            NeuralChannel {
                id: 3,
                channel_type: ChannelType::Sensory,
                sample_rate: 500,
                quality: 0.88,
            },
        ];

        Self {
            device_id,
            signing_key,
            firmware_hash,
            model_hash,
            previous_commitment: None,
            sequence: 0,
            channels,
            mode: DeviceMode::Normal,
        }
    }

    /// Get device ID
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Get available channels
    pub fn channels(&self) -> &[NeuralChannel] {
        &self.channels
    }

    /// Set device mode
    pub fn set_mode(&mut self, mode: DeviceMode) {
        self.mode = mode;
    }

    /// Generate a neural frame with simulated data
    pub fn generate_frame(&mut self) -> Result<NeuralFrame> {
        let timestamp = Utc::now();

        // Generate simulated neural signal data
        let signal_data = self.generate_signal_data();

        // Decode the signal (simulated)
        let decoded_output = self.decode_signal(&signal_data);

        // Compute transformation hash
        let transformation_hash = self.compute_transformation_hash();

        // Fresh nonce per frame, so identical content still yields distinct commitments
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill(&mut nonce);

        let sequence = self.sequence;
        self.sequence += 1;

        // Create the frame
        let mut frame = NeuralFrame {
            device_id: self.device_id.clone(),
            firmware_hash: self.firmware_hash,
            timestamp,
            transformation_hash,
            model_hash: self.model_hash,
            previous_commitment: self.previous_commitment,
            sequence,
            nonce,
            signal_data,
            decoded_output,
            signature: [0u8; 64], // Placeholder
        };

        // Apply attack modifications if in attack mode
        if let DeviceMode::AttackSimulation(attack_type) = self.mode {
            self.apply_attack(&mut frame, attack_type);
        }

        // Sign the frame
        let signable_data = frame.signable_data();
        let signature: Signature = self.signing_key.sign(&signable_data);
        frame.signature = signature.to_bytes();

        // Update previous commitment for next frame
        self.previous_commitment = Some(frame.compute_commitment());

        Ok(frame)
    }

    /// Generate simulated neural signal data
    fn generate_signal_data(&self) -> Vec<f32> {
        let mut rng = rand::thread_rng();
        let num_samples = 100;

        (0..num_samples)
            .map(|i| {
                // Simulate a sinusoidal pattern with noise
                let t = i as f32 / num_samples as f32;
                let signal = (t * 2.0 * std::f32::consts::PI * 5.0).sin();
                let noise = rng.gen::<f32>() * 0.1 - 0.05;
                signal + noise
            })
            .collect()
    }

    /// Decode neural signal (simulated)
    fn decode_signal(&self, _signal_data: &[f32]) -> DecodedOutput {
        let mut rng = rand::thread_rng();

        match self.mode {
            DeviceMode::Normal => {
                // Simulate cursor position
                DecodedOutput::CursorPosition {
                    x: rng.gen_range(0.0..1920.0),
                    y: rng.gen_range(0.0..1080.0),
                }
            }
            DeviceMode::AttackSimulation(AttackType::CommandModification) => {
                // Inject malicious command
                DecodedOutput::Command("MALICIOUS_COMMAND".to_string())
            }
            _ => DecodedOutput::CursorPosition {
                x: rng.gen_range(0.0..1920.0),
                y: rng.gen_range(0.0..1080.0),
            },
        }
    }

    /// Compute transformation hash
    fn compute_transformation_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"neural-decoder-v1.0");
        hasher.update(self.model_hash);
        hasher.finalize().into()
    }

    /// Apply attack modifications to a frame
    fn apply_attack(&mut self, frame: &mut NeuralFrame, attack_type: AttackType) {
        match attack_type {
            AttackType::ReplayAttack => {
                // Use old timestamp
                frame.timestamp = Utc::now() - chrono::Duration::minutes(10);
            }
            AttackType::SignalInjection => {
                // Inject abnormal signal
                frame.signal_data = vec![999.9; 100];
            }
            AttackType::MaliciousDecoder => {
                // Use wrong model hash
                frame.model_hash = [0xFF; 32];
            }
            AttackType::FirmwareDowngrade => {
                // Use older firmware hash
                frame.firmware_hash = [0x01; 32];
            }
            AttackType::DeviceImpersonation => {
                // Try to impersonate another device (signature will fail)
                frame.device_id.id = "impersonated-device".to_string();
            }
            AttackType::TamperedCalibration => {
                // Corrupt transformation hash
                frame.transformation_hash = [0xAA; 32];
            }
            AttackType::CommandModification => {
                // Modify decoded output (already handled in decode_signal)
            }
            AttackType::DataExfiltration => {
                // Exfiltrate raw signal data (no modification, just logging)
                // In a real scenario, this would send data to attacker
            }
        }
    }

    /// Compute firmware hash
    fn compute_firmware_hash(firmware: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(firmware);
        hasher.finalize().into()
    }

    /// Compute model hash
    fn compute_model_hash(model: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(model);
        hasher.finalize().into()
    }

    /// Upgrade firmware (changes firmware hash)
    pub fn upgrade_firmware(&mut self, new_firmware: &[u8]) {
        self.firmware_hash = Self::compute_firmware_hash(new_firmware);
    }

    /// Update decoder model
    pub fn update_model(&mut self, new_model: &[u8]) {
        self.model_hash = Self::compute_model_hash(new_model);
    }
}

/// BCI attack simulator
pub struct AttackSimulator {
    device: VirtualBCI,
}

impl AttackSimulator {
    /// Create a new attack simulator
    pub fn new(device: VirtualBCI) -> Self {
        Self { device }
    }

    /// Run an attack scenario and return frames
    pub fn run_attack(
        &mut self,
        attack_type: AttackType,
        num_frames: usize,
    ) -> Result<Vec<NeuralFrame>> {
        self.device
            .set_mode(DeviceMode::AttackSimulation(attack_type));

        let mut frames = Vec::new();
        for _ in 0..num_frames {
            frames.push(self.device.generate_frame()?);
        }

        // Reset to normal mode
        self.device.set_mode(DeviceMode::Normal);

        Ok(frames)
    }

    /// Get the underlying device
    pub fn device(&self) -> &VirtualBCI {
        &self.device
    }

    /// Get mutable access to the device
    pub fn device_mut(&mut self) -> &mut VirtualBCI {
        &mut self.device
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_bci_creation() {
        let bci = VirtualBCI::new(
            "test-device-001".to_string(),
            "TestCo".to_string(),
            "TestImplant-V1".to_string(),
        );

        assert_eq!(bci.device_id().id, "test-device-001");
        assert_eq!(bci.channels().len(), 3);
    }

    #[test]
    fn test_frame_generation() {
        let mut bci = VirtualBCI::new(
            "test-device-001".to_string(),
            "TestCo".to_string(),
            "TestImplant-V1".to_string(),
        );

        let frame = bci.generate_frame().unwrap();

        assert_eq!(frame.device_id.id, "test-device-001");
        assert!(!frame.signal_data.is_empty());
        assert_eq!(frame.signature.len(), 64);
    }

    #[test]
    fn test_attack_simulation() {
        let bci = VirtualBCI::new(
            "test-device-001".to_string(),
            "TestCo".to_string(),
            "TestImplant-V1".to_string(),
        );

        let mut simulator = AttackSimulator::new(bci);

        let attack_frames = simulator.run_attack(AttackType::ReplayAttack, 5).unwrap();

        assert_eq!(attack_frames.len(), 5);
    }

    #[test]
    fn test_provenance_chain() {
        let mut bci = VirtualBCI::new(
            "test-device-001".to_string(),
            "TestCo".to_string(),
            "TestImplant-V1".to_string(),
        );

        let frame1 = bci.generate_frame().unwrap();
        assert!(frame1.previous_commitment.is_none()); // First frame

        let frame2 = bci.generate_frame().unwrap();
        assert!(frame2.previous_commitment.is_some()); // Should chain to frame1

        let commitment1 = frame1.compute_commitment();
        assert_eq!(frame2.previous_commitment.unwrap(), commitment1);
    }
}
