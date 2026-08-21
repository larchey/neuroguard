//! BCI attack scenario demonstration

use neuroguard::{
    attestation::{DeviceRegistry, TrustLevel},
    verify_frame,
    virtual_bci::{AttackSimulator, AttackType, VirtualBCI},
};

fn main() -> neuroguard::Result<()> {
    println!("NeuroGuard Attack Scenario Simulator");
    println!("====================================\n");

    let attack_types = [
        AttackType::ReplayAttack,
        AttackType::SignalInjection,
        AttackType::MaliciousDecoder,
        AttackType::FirmwareDowngrade,
        AttackType::DeviceImpersonation,
        AttackType::TamperedCalibration,
        AttackType::CommandModification,
        AttackType::DataExfiltration,
    ];

    let mut detected = 0usize;
    let mut total = 0usize;

    for attack_type in &attack_types {
        println!("Testing attack: {:?}", attack_type);
        println!("{}", "-".repeat(60));

        // Create a virtual BCI
        let bci = VirtualBCI::new(
            "attack-test-device".to_string(),
            "AttackSimCo".to_string(),
            "TestImplant-V1".to_string(),
        );

        // Enrol the genuine device, so verification has a key to check against
        let mut registry = DeviceRegistry::new();
        registry
            .register_device(bci.enrol(TrustLevel::FullyTrusted, vec!["decoder-v1".to_string()]));

        // Create attack simulator
        let mut simulator = AttackSimulator::new(bci);

        // Run the attack
        let attack_frames = simulator.run_attack(*attack_type, 3)?;

        for (i, frame) in attack_frames.iter().enumerate() {
            println!("\nAttack Frame {}:", i + 1);
            total += 1;

            // Try to verify the frame
            match verify_frame(frame, &registry) {
                Ok(report) => {
                    println!("  Verdict: {:?}", report.verdict);
                    println!("  Device authenticated: {}", report.device_authenticated);
                    println!("  Firmware trusted: {}", report.firmware_trusted);
                    println!("  Provenance intact: {}", report.provenance_intact);

                    for detail in &report.details {
                        println!("    {}", detail);
                    }

                    if report.verdict != neuroguard::attestation::Verdict::Trusted {
                        detected += 1;
                        println!("  ✓ Attack rejected!");
                    } else {
                        println!("  ⚠️  Attack bypassed verification!");
                    }
                }
                Err(e) => {
                    detected += 1;
                    println!("  ✓ Attack DETECTED: {}", e);
                }
            }
        }

        println!("\n");
    }

    println!("\n{}", "=".repeat(60));
    println!("Attack Scenario Summary");
    println!("{}", "=".repeat(60));
    println!("Tested {} attack types", attack_types.len());
    println!("Frames rejected: {detected} of {total}");
    println!(
        "\nNote: every scenario tampers with the frame *before* the device signs it, so each one"
    );
    println!(
        "carries a valid signature from a genuinely enrolled device. This models a compromised"
    );
    println!("device; it cannot express an attacker on the link. Scenarios that tamper after");
    println!("signing are still to be written — see docs/THREAT_MODEL.md §8.");
    println!("\nNext Steps:");
    println!("  1. Wire firmware and model approval into the pipeline");
    println!("  2. Enforce sequence monotonicity and a freshness window");
    println!("  3. Implement signal anomaly detection");
    println!("  4. Add rate limiting and admission control");

    Ok(())
}
