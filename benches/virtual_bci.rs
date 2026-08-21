use criterion::{black_box, criterion_group, criterion_main, Criterion};
use neuroguard::attestation::{DeviceRegistry, TrustLevel};
use neuroguard::virtual_bci::VirtualBCI;

fn bench_frame_generation(c: &mut Criterion) {
    c.bench_function("generate_frame", |b| {
        let mut bci = VirtualBCI::new(
            "bench-device".to_string(),
            "BenchCo".to_string(),
            "V1".to_string(),
        );

        b.iter(|| {
            black_box(bci.generate_frame().unwrap());
        });
    });
}

fn bench_frame_verification(c: &mut Criterion) {
    c.bench_function("verify_frame", |b| {
        let mut bci = VirtualBCI::new(
            "bench-device".to_string(),
            "BenchCo".to_string(),
            "V1".to_string(),
        );

        let mut registry = DeviceRegistry::new();
        registry.register_device(bci.enrol(TrustLevel::FullyTrusted, Vec::new()));

        let frame = bci.generate_frame().unwrap();

        b.iter(|| {
            black_box(neuroguard::verify_frame(&frame, &registry).unwrap());
        });
    });
}

criterion_group!(benches, bench_frame_generation, bench_frame_verification);
criterion_main!(benches);
