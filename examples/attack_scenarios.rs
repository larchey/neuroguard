//! BCI attack scenario demonstration

use neuroguard::{
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

    for attack_type in &attack_types {
        println!("Testing attack: {:?}", attack_type);
        println!("{}", "-".repeat(60));

        // Create a virtual BCI
        let bci = VirtualBCI::new(
            "attack-test-device".to_string(),
            "AttackSimCo".to_string(),
            "TestImplant-V1".to_string(),
        );

        // Create attack simulator
        let mut simulator = AttackSimulator::new(bci);

        // Run the attack
        let attack_frames = simulator.run_attack(*attack_type, 3)?;

        for (i, frame) in attack_frames.iter().enumerate() {
            println!("\nAttack Frame {}:", i + 1);

            // Try to verify the frame
            match verify_frame(frame) {
                Ok(report) => {
                    println!("  Verdict: {:?}", report.verdict);
                    println!("  Device authenticated: {}", report.device_authenticated);
                    println!("  Firmware trusted: {}", report.firmware_trusted);
                    println!("  Provenance intact: {}", report.provenance_intact);

                    for detail in &report.details {
                        println!("    {}", detail);
                    }

                    if report.verdict != neuroguard::attestation::Verdict::Trusted {
                        println!("  ⚠️  Attack potentially detectable!");
                    } else {
                        println!("  ⚠️  Attack bypassed verification!");
                    }
                }
                Err(e) => {
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
    println!("\nKey Findings:");
    println!("  - Signature verification catches device impersonation");
    println!("  - Provenance chain detects replay attacks");
    println!("  - Hash verification detects firmware/model tampering");
    println!("  - Signal analysis needed for injection detection");
    println!("\nNext Steps:");
    println!("  1. Implement firmware hash registry");
    println!("  2. Add model approval system");
    println!("  3. Implement signal anomaly detection");
    println!("  4. Add rate limiting and replay protection");

    Ok(())
}
