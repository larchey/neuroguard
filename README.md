# NeuroGuard

Security middleware and virtual testing framework for brain-computer interfaces (BCIs).

## Overview

NeuroGuard provides cryptographic attestation, provenance tracking, and policy enforcement for neural interfaces. As BCIs move from research to production, they require the same security infrastructure that protects spacecraft telemetry, industrial control systems, and medical devices.

**Current Status**: v0.0.1 - Early research prototype

## Why NeuroGuard?

Brain-computer interfaces present unique security challenges:

- **Safety-critical control**: BCIs may control wheelchairs, prosthetics, speech synthesizers, or vehicles
- **Signal provenance**: Ensuring neural signals haven't been replayed, modified, or injected
- **Device attestation**: Verifying firmware integrity and decoder model authenticity
- **Application isolation**: Enforcing least-privilege access to neural channels
- **Attack surface**: Wireless links, decoder models, calibration data, and signal processing chains

NeuroGuard addresses these challenges before they become production incidents.

## Features

### Security Primitives

- **Device Attestation**: Ed25519-based device authentication
- **Firmware Verification**: SHA-256 hash chains for firmware integrity
- **Signal Provenance**: Cryptographic chain of custody for neural data
- **Capability-based Access Control**: Fine-grained permissions for applications
- **Model Verification**: Decoder and ML model hash validation

### Virtual BCI Simulator

- Simulated neural device with configurable channels
- Support for motor cortex, sensory, visual, and auditory signals
- Realistic signal generation with noise modeling
- Provenance chain generation

### Attack Framework

NeuroGuard includes a cyber range for BCI security research:

- **Replay attacks**: Retransmitting old neural commands
- **Signal injection**: Malicious signal insertion
- **Malicious decoder**: Compromised ML models
- **Firmware downgrade**: Rolling back to vulnerable versions
- **Device impersonation**: Spoofing trusted implants
- **Calibration tampering**: Corrupted signal processing
- **Command modification**: Altering decoded outputs
- **Data exfiltration**: Unauthorized signal recording

## Quick Start

```bash
cargo add neuroguard
```

### Basic Usage

```rust
use neuroguard::{
    virtual_bci::VirtualBCI,
    verify_frame,
};

fn main() -> neuroguard::Result<()> {
    // Create a virtual BCI device
    let mut bci = VirtualBCI::new(
        "device-001".to_string(),
        "NeuroCorp".to_string(),
        "Implant-V1".to_string(),
    );

    // Generate a neural frame
    let frame = bci.generate_frame()?;

    // Verify the frame
    let report = verify_frame(&frame)?;

    println!("Verification verdict: {:?}", report.verdict);

    Ok(())
}
```

### Attack Simulation

```rust
use neuroguard::virtual_bci::{AttackSimulator, AttackType, VirtualBCI};

let bci = VirtualBCI::new(
    "test-device".to_string(),
    "TestCo".to_string(),
    "V1".to_string(),
);

let mut simulator = AttackSimulator::new(bci);

// Simulate a replay attack
let attack_frames = simulator.run_attack(
    AttackType::ReplayAttack,
    10
)?;

// Attempt to verify compromised frames
for frame in &attack_frames {
    let report = verify_frame(frame)?;
    println!("Attack detected: {:?}", report.verdict);
}
```

## Examples

```bash
# Basic BCI usage
cargo run --example basic_bci

# Attack scenario demonstration
cargo run --example attack_scenarios
```

## Architecture

```
┌─────────────────────┐
│  BCI Application    │
│   (cursor, speech)  │
└──────────┬──────────┘
           │
    ┌──────▼──────────┐
    │  NeuroGuard SDK │
    ├─────────────────┤
    │ Policy Engine   │
    │ Attestation     │
    │ Provenance      │
    └──────┬──────────┘
           │
    ┌──────▼──────────┐
    │  Signal Gateway │
    └──────┬──────────┘
           │
┌──────────┴──────────────┐
│                         │
│  Virtual BCI      Real BCI │
│  (testing)         (hw)    │
└─────────────────────────┘
```

## Verification Flow

For each neural frame:

1. ✓ **Device authentication**: Verify Ed25519 signature
2. ✓ **Firmware integrity**: Check SHA-256 hash against approved list
3. ✓ **Decoder approval**: Validate ML model hash
4. ✓ **Provenance chain**: Verify hash chain continuity
5. ✓ **Policy compliance**: Enforce capability-based access
6. ✓ **Application authorization**: Check app permissions

## Security Model

NeuroGuard follows defense-in-depth principles:

- **Cryptographic attestation** (device identity)
- **Hash-based integrity** (firmware, models, transformations)
- **Provenance chains** (tamper-evident logs)
- **Least-privilege access** (capability-based)
- **Fail-secure defaults** (deny-by-default)

## Roadmap

### v0.1.0 (Next)
- [ ] Firmware registry integration
- [ ] Model approval workflow
- [ ] Signal anomaly detection
- [ ] Rate limiting and replay protection
- [ ] TLS transport layer

### v0.2.0
- [ ] Hardware device integration
- [ ] WebAssembly support
- [ ] Audit logging
- [ ] Compliance reporting (FDA, CE mark)

### v1.0.0
- [ ] Production-ready attestation
- [ ] Formal security audit
- [ ] Reference implementation for major BCI platforms
- [ ] FIPS 140-3 compliance

## Research Applications

NeuroGuard is designed for:

- **Security researchers**: Study BCI attack vectors
- **BCI developers**: Integrate security early in design
- **Universities**: Teach neural interface security
- **Standards bodies**: Prototype security frameworks

## Prior Art

NeuroGuard draws inspiration from:

- **Spacecraft security**: Remote attestation, telemetry integrity
- **Medical device security**: FDA cybersecurity guidance
- **Embedded systems**: Secure boot, measured boot
- **Post-quantum cryptography**: Lattice-based primitives (future work)

## Contributing

This is a research prototype. Contributions welcome:

- Attack scenario implementations
- Hardware device integrations
- Formal verification proofs
- Standards documentation

## License

Dual-licensed under MIT OR Apache-2.0.

## Disclaimer

**NOT FOR PRODUCTION USE**. This is a research prototype. Do not use with actual medical devices or safety-critical systems without formal security audit and regulatory approval.

## Author

Charley Hoffman (charley.hoffm@gmail.com)

Background: Platform security + satellite communications → post-quantum cryptography (TURTL, Pulse) → BCI security

## References

- [FDA Cybersecurity for Medical Devices](https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Spacecraft Security](https://www.nasa.gov/offices/oct/home/roadmaps/index.html)
