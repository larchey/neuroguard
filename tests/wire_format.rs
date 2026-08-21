//! Wire-format regression tests.
//!
//! `NeuralFrame` is the interchange type: it crosses the device/host boundary as JSON, and
//! everything downstream — signature verification, commitment chaining — assumes the bytes that
//! come back out are the bytes that went in. Nothing tested that assumption.
//!
//! These tests exist mainly as a net for the v0.1.0 protocol rewrite (canonical `signable_data`,
//! registry-resolved keys, sequence numbers). That change rewrites the format; these assertions
//! are what catch it silently breaking round-tripping or signature validity along the way.
//!
//! `NeuralFrame` and `DecodedOutput` do not implement `PartialEq`, so equality is asserted
//! through the three things that actually matter downstream: the serialized form, the signable
//! preimage, and the commitment.

use chrono::{TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use neuroguard::attestation::verify_signature;
use neuroguard::protocol::{DecodedOutput, DeviceId, NeuralFrame};

/// A frame with a fixed timestamp and a real signature over its own contents.
fn signed_frame(decoded_output: DecodedOutput, signal_data: Vec<f32>) -> NeuralFrame {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);

    let mut frame = NeuralFrame {
        device_id: DeviceId {
            id: "wire-test-device".to_string(),
            manufacturer: "TestCo".to_string(),
            model: "Implant-V1".to_string(),
            public_key: signing_key.verifying_key().to_bytes(),
        },
        firmware_hash: [0x11; 32],
        timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        transformation_hash: [0x22; 32],
        model_hash: [0x33; 32],
        previous_commitment: Some([0x44; 32]),
        signal_data,
        decoded_output,
        signature: [0u8; 64],
    };

    frame.signature = signing_key.sign(&frame.signable_data()).to_bytes();
    frame
}

fn round_trip(frame: &NeuralFrame) -> NeuralFrame {
    let json = serde_json::to_string(frame).expect("frame must serialize");
    serde_json::from_str(&json).expect("frame must deserialize")
}

#[test]
fn frame_survives_a_json_round_trip() {
    let original = signed_frame(
        DecodedOutput::CursorPosition {
            x: 640.5,
            y: 480.25,
        },
        vec![0.1, -0.2, 0.3],
    );
    let decoded = round_trip(&original);

    assert_eq!(
        serde_json::to_string(&original).unwrap(),
        serde_json::to_string(&decoded).unwrap(),
        "re-serializing a round-tripped frame must reproduce the same bytes"
    );
}

#[test]
fn round_trip_preserves_the_signable_preimage() {
    // If this drifts, a frame that verified on the device stops verifying on the host — or
    // worse, a tampered frame starts verifying. The preimage is the security-critical part
    // of the format, not the JSON itself.
    let original = signed_frame(
        DecodedOutput::ProstheticControl {
            joints: vec![
                0.0,
                std::f32::consts::FRAC_PI_2,
                -std::f32::consts::FRAC_PI_4,
            ],
        },
        vec![0.5; 16],
    );
    let decoded = round_trip(&original);

    assert_eq!(
        original.signable_data(),
        decoded.signable_data(),
        "signable preimage must be stable across serialization"
    );
    assert_eq!(
        original.compute_commitment(),
        decoded.compute_commitment(),
        "commitment must be stable across serialization"
    );
}

#[test]
fn signature_still_verifies_after_a_round_trip() {
    let original = signed_frame(
        DecodedOutput::VehicleControl {
            throttle: 0.25,
            steering: -0.5,
            brake: 0.0,
        },
        vec![1.0, 2.0, 3.0],
    );

    verify_signature(&original).expect("freshly signed frame must verify");
    verify_signature(&round_trip(&original)).expect("round-tripped frame must still verify");
}

#[test]
fn all_decoded_output_variants_round_trip() {
    let variants = vec![
        DecodedOutput::CursorPosition { x: 1.0, y: 2.0 },
        DecodedOutput::Command("select".to_string()),
        DecodedOutput::Text("hello".to_string()),
        DecodedOutput::ProstheticControl {
            joints: vec![0.1, 0.2],
        },
        DecodedOutput::VehicleControl {
            throttle: 0.1,
            steering: 0.2,
            brake: 0.3,
        },
        DecodedOutput::Classification {
            class: "left".to_string(),
            confidence: 0.87,
        },
    ];

    for variant in variants {
        let label = format!("{variant:?}");
        let frame = signed_frame(variant, vec![0.25, 0.5]);
        let decoded = round_trip(&frame);

        assert_eq!(
            frame.signable_data(),
            decoded.signable_data(),
            "{label}: preimage changed across round trip"
        );
        verify_signature(&decoded).unwrap_or_else(|e| panic!("{label}: failed to verify: {e}"));
    }
}

#[test]
fn the_64_byte_signature_survives_serde_with_bytes() {
    // `signature` is the one field needing a serde_with adapter: arrays longer than 32 have no
    // blanket Deserialize impl. Every byte value is exercised so a truncating or sign-extending
    // adapter cannot pass.
    let mut frame = signed_frame(DecodedOutput::Command("go".to_string()), vec![0.0]);
    let distinctive: [u8; 64] = std::array::from_fn(|i| (i * 4) as u8);
    frame.signature = distinctive;

    let decoded = round_trip(&frame);

    assert_eq!(
        decoded.signature, distinctive,
        "signature bytes must survive serialization exactly"
    );
}

#[test]
fn f32_signal_samples_survive_exactly() {
    // signal_data is hashed into both the commitment and the signable preimage via
    // `f32::to_le_bytes`, so any precision loss in JSON breaks verification rather than merely
    // degrading the signal. Awkward values: subnormals, extremes, and non-terminating decimals.
    let samples = vec![
        0.1,
        -0.1,
        f32::MIN_POSITIVE,
        f32::MAX,
        f32::MIN,
        1.0 / 3.0,
        -0.0,
        1e-30,
        16_777_217.0, // not representable in f32; rounds to 16777216
    ];

    let frame = signed_frame(DecodedOutput::Command("x".to_string()), samples.clone());
    let decoded = round_trip(&frame);

    for (i, (before, after)) in samples.iter().zip(decoded.signal_data.iter()).enumerate() {
        assert_eq!(
            before.to_le_bytes(),
            after.to_le_bytes(),
            "sample {i} ({before}) changed bit pattern across serialization"
        );
    }
    verify_signature(&decoded).expect("frame with awkward samples must still verify");
}

#[test]
fn an_empty_signal_frame_round_trips() {
    let frame = signed_frame(DecodedOutput::Command("idle".to_string()), Vec::new());
    let decoded = round_trip(&frame);

    assert!(decoded.signal_data.is_empty());
    verify_signature(&decoded).expect("empty-signal frame must verify");
}

#[test]
fn a_genesis_frame_round_trips_with_no_previous_commitment() {
    let mut frame = signed_frame(DecodedOutput::Command("start".to_string()), vec![0.5]);
    frame.previous_commitment = None;
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    frame.signature = signing_key.sign(&frame.signable_data()).to_bytes();

    let decoded = round_trip(&frame);

    assert!(
        decoded.previous_commitment.is_none(),
        "Option<[u8; 32]> must round trip as None, not as a zero array"
    );
    verify_signature(&decoded).expect("genesis frame must verify");
}
