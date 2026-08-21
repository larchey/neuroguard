//! Basic BCI usage example

use neuroguard::{
    attestation::{DeviceRegistry, TrustLevel, TrustedDevice},
    policy::{Capability, PolicyEngine},
    protocol::NeuralChannel,
    virtual_bci::VirtualBCI,
    verify_frame,
};

fn main() -> neuroguard::Result<()> {
    println!("NeuroGuard Basic BCI Example");
    println!("============================\n");

    // 1. Create a virtual BCI device
    println!("Creating virtual BCI device...");
    let mut bci = VirtualBCI::new(
        "neuro-device-001".to_string(),
        "NeuroCorp".to_string(),
        "Implant-V1".to_string(),
    );

    println!("Device ID: {}", bci.device_id().id);
    println!("Manufacturer: {}", bci.device_id().manufacturer);
    println!("Model: {}", bci.device_id().model);
    println!("Channels: {}", bci.channels().len());

    for channel in bci.channels() {
        println!(
            "  - Channel {} ({:?}): {} Hz, quality {:.2}",
            channel.id, channel.channel_type, channel.sample_rate, channel.quality
        );
    }

    // 2. Set up device registry
    println!("\nRegistering device in trust registry...");
    let mut registry = DeviceRegistry::new();

    let trusted_device = TrustedDevice {
        device_id: bci.device_id().clone(),
        trust_level: TrustLevel::FullyTrusted,
        allowed_decoders: vec!["decoder-v1".to_string()],
    };

    registry.register_device(trusted_device);

    // 3. Set up policy engine
    println!("Setting up policy engine...");
    let mut policy_engine = PolicyEngine::new();

    let app_policy = PolicyEngine::default_dev_policy("cursor-app".to_string());
    policy_engine.register_policy(app_policy);

    // 4. Generate and verify frames
    println!("\nGenerating neural frames...\n");

    for i in 1..=5 {
        // Generate a frame from the virtual BCI
        let frame = bci.generate_frame()?;

        println!("Frame {}:", i);
        println!("  Timestamp: {}", frame.timestamp);
        println!("  Signal samples: {}", frame.signal_data.len());
        println!("  Decoded output: {:?}", frame.decoded_output);

        // Verify the frame
        let report = verify_frame(&frame)?;

        println!("  Verification report:");
        println!("    Device authenticated: {}", report.device_authenticated);
        println!("    Firmware trusted: {}", report.firmware_trusted);
        println!("    Provenance intact: {}", report.provenance_intact);
        println!("    Verdict: {:?}", report.verdict);

        for detail in &report.details {
            println!("      {}", detail);
        }

        // Check policy compliance
        match policy_engine.check_capability("cursor-app", Capability::ReadDecodedOutput) {
            Ok(()) => println!("  ✓ Application authorized to read decoded output"),
            Err(e) => println!("  ✗ Authorization failed: {}", e),
        }

        println!();
    }

    println!("All frames processed successfully!");

    Ok(())
}
