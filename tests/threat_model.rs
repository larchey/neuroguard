//! Tests that keep `docs/THREAT_MODEL.md` and `docs/threat-catalog.json` honest.
//!
//! Two kinds of test live here:
//!
//! 1. **Consistency tests** — the catalogue, the prose document, and the `AttackType` enum must
//!    agree. Adding an attack scenario without modelling it fails the build.
//! 2. **Characterisation tests** — each asserts the *current, vulnerable* behaviour of a threat
//!    marked `OPEN`, with the threat ID in the name. They are expected to fail when the
//!    corresponding fix lands; that failure is the signal to update the catalogue status and
//!    rewrite the test to assert the fixed behaviour.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use neuroguard::attestation::{verify_neural_frame, verify_signature, Verdict};
use neuroguard::policy::{Capability, PolicyEngine};
use neuroguard::protocol::DecodedOutput;
use neuroguard::provenance::ProvenanceChain;
use neuroguard::virtual_bci::{AttackSimulator, AttackType, VirtualBCI};
use sha2::{Digest, Sha256};

fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn catalog() -> serde_json::Value {
    let raw = fs::read_to_string(repo_path("docs/threat-catalog.json"))
        .expect("docs/threat-catalog.json must exist");
    serde_json::from_str(&raw).expect("threat catalogue must be valid JSON")
}

fn catalog_ids(cat: &serde_json::Value) -> Vec<String> {
    cat["threats"]
        .as_array()
        .expect("threats must be an array")
        .iter()
        .map(|t| {
            t["id"]
                .as_str()
                .expect("every threat needs an id")
                .to_string()
        })
        .collect()
}

/// Every `NG-Tnnn` token appearing in a body of text.
fn threat_ids_in(text: &str) -> HashSet<String> {
    let bytes = text.as_bytes();
    let mut found = HashSet::new();
    for (i, _) in text.match_indices("NG-T") {
        let digits = &bytes[i + 4..];
        if digits.len() >= 3 && digits[..3].iter().all(u8::is_ascii_digit) {
            found.insert(format!("NG-T{}", String::from_utf8_lossy(&digits[..3])));
        }
    }
    found
}

// ---------------------------------------------------------------------------
// Consistency
// ---------------------------------------------------------------------------

#[test]
fn catalog_ids_are_unique_and_well_formed() {
    let cat = catalog();
    let ids = catalog_ids(&cat);
    let unique: HashSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "duplicate threat id in catalogue");

    for id in &ids {
        assert!(id.starts_with("NG-T"), "malformed threat id: {id}");
        assert_eq!(id.len(), 7, "threat ids are NG-Tnnn: {id}");
        assert!(
            id[4..].chars().all(|c| c.is_ascii_digit()),
            "threat ids end in three digits: {id}"
        );
    }
}

#[test]
fn every_catalog_threat_has_required_fields() {
    let cat = catalog();
    for threat in cat["threats"].as_array().unwrap() {
        let id = threat["id"].as_str().unwrap();
        for field in ["title", "severity", "status", "mitigation", "roadmap"] {
            let value = threat[field].as_str();
            assert!(
                value.is_some_and(|v| !v.trim().is_empty()),
                "{id} is missing `{field}`"
            );
        }
        let severity = threat["severity"].as_str().unwrap();
        assert!(
            ["critical", "high", "medium", "low"].contains(&severity),
            "{id} has unknown severity `{severity}`"
        );
        let status = threat["status"].as_str().unwrap();

        // A closed threat must say what closed it, so the catalogue records the fix rather
        // than quietly dropping the finding.
        if status == "closed" {
            let resolution = threat["resolution"].as_str();
            assert!(
                resolution.is_some_and(|r| r.trim().len() > 40),
                "{id} is closed but has no substantive `resolution`"
            );
        }

        assert!(
            ["open", "partial", "design", "closed"].contains(&status),
            "{id} has unknown status `{status}`"
        );
        for dim in ["s", "p", "f"] {
            let score = threat["impact"][dim].as_u64().unwrap_or(99);
            assert!(score <= 4, "{id} impact.{dim} must be 0-4");
        }
        let likelihood = threat["likelihood"].as_u64().unwrap_or(0);
        assert!((1..=5).contains(&likelihood), "{id} likelihood must be 1-5");

        // A threat that claims no mitigation path is a documentation bug.
        assert!(
            threat["mitigation"].as_str().unwrap().len() > 40,
            "{id} needs a substantive mitigation, not a placeholder"
        );
    }
}

#[test]
fn catalog_and_document_describe_the_same_threats() {
    let cat = catalog();
    let doc = fs::read_to_string(repo_path("docs/THREAT_MODEL.md")).expect("threat model doc");

    let in_catalog: HashSet<String> = catalog_ids(&cat).into_iter().collect();
    let in_doc = threat_ids_in(&doc);

    let undocumented: Vec<_> = in_catalog.difference(&in_doc).collect();
    assert!(
        undocumented.is_empty(),
        "catalogued but absent from THREAT_MODEL.md: {undocumented:?}"
    );

    let uncatalogued: Vec<_> = in_doc.difference(&in_catalog).collect();
    assert!(
        uncatalogued.is_empty(),
        "referenced in THREAT_MODEL.md but not catalogued: {uncatalogued:?}"
    );
}

/// Variant names of `AttackType`, read from the source so a rename or addition is caught here
/// rather than silently drifting away from the threat model.
fn attack_type_variants() -> Vec<String> {
    let src = fs::read_to_string(repo_path("src/virtual_bci.rs")).expect("virtual_bci source");
    let start = src
        .find("pub enum AttackType {")
        .expect("AttackType enum must exist");
    let body = &src[start..];
    let end = body.find("\n}").expect("AttackType enum must be closed");

    body[..end]
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with("//")
                && line.ends_with(',')
                && !line.contains(' ')
        })
        .map(|line| line.trim_end_matches(',').to_string())
        .collect()
}

#[test]
fn every_attack_scenario_maps_to_a_modelled_threat() {
    let variants = attack_type_variants();
    assert!(
        variants.len() >= 8,
        "expected to parse the AttackType variants, got {variants:?}"
    );

    let cat = catalog();
    let mut simulated: HashSet<String> = HashSet::new();
    for threat in cat["threats"].as_array().unwrap() {
        for scenario in threat["simulated_by"].as_array().unwrap() {
            simulated.insert(scenario.as_str().unwrap().to_string());
        }
    }

    let unmodelled: Vec<_> = variants
        .iter()
        .filter(|v| !simulated.contains(*v))
        .collect();
    assert!(
        unmodelled.is_empty(),
        "AttackType variants with no catalogued threat (add them to docs/threat-catalog.json): {unmodelled:?}"
    );
}

#[test]
fn proposed_scenarios_are_not_yet_implemented_variants() {
    // Keeps §8.2 honest: once a proposed scenario ships as an AttackType, it should move from
    // `proposed_scenarios` to `simulated_by`.
    let variants: HashSet<String> = attack_type_variants().into_iter().collect();
    let cat = catalog();
    for threat in cat["threats"].as_array().unwrap() {
        let id = threat["id"].as_str().unwrap();
        for proposed in threat["proposed_scenarios"].as_array().unwrap() {
            let name = proposed.as_str().unwrap();
            assert!(
                !variants.contains(name),
                "{id}: `{name}` now exists as an AttackType — move it to simulated_by"
            );
        }
    }
}

#[test]
fn catalog_code_references_point_at_real_lines() {
    let cat = catalog();
    for threat in cat["threats"].as_array().unwrap() {
        let id = threat["id"].as_str().unwrap();
        for reference in threat["code_refs"].as_array().unwrap() {
            let reference = reference.as_str().unwrap();
            let (file, line) = reference
                .rsplit_once(':')
                .unwrap_or_else(|| panic!("{id}: code ref `{reference}` needs a line number"));
            let line: usize = line
                .parse()
                .unwrap_or_else(|_| panic!("{id}: `{reference}` has a non-numeric line"));
            let source = fs::read_to_string(repo_path(file))
                .unwrap_or_else(|_| panic!("{id}: `{reference}` points at a missing file"));
            let total = source.lines().count();
            assert!(
                line >= 1 && line <= total,
                "{id}: `{reference}` is out of range (file has {total} lines)"
            );

            // A range check alone lets references rot silently: insert lines above a
            // reference and it slides onto unrelated code while the test stays green.
            // Pinning exact text would duplicate the source into the catalogue, but we can
            // reject the shapes a drifted reference tends to land on — blank lines, bare
            // delimiters, doc comments, and attributes are never worth citing on their own.
            let target = source.lines().nth(line - 1).unwrap().trim();
            assert!(
                !target.is_empty()
                    && !matches!(target, "}" | "{" | ")" | "};" | ");")
                    && !target.starts_with("///")
                    && !target.starts_with("//!")
                    && !target.starts_with("#["),
                "{id}: `{reference}` points at `{target}`, which is not citable code — \
                 the reference has probably drifted"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Characterisation: current behaviour of OPEN threats
// ---------------------------------------------------------------------------

fn device(name: &str) -> VirtualBCI {
    VirtualBCI::new(
        name.to_string(),
        "ThreatModelCo".to_string(),
        "TM-V1".to_string(),
    )
}

/// NG-T010 (CLOSED): `signable_data()` covers `decoded_output`, so rewriting the command in
/// flight invalidates the device signature.
#[test]
fn ng_t010_decoded_output_is_covered_by_the_signature() {
    let mut bci = device("t010");
    let mut frame = bci.generate_frame().unwrap();
    assert!(
        verify_signature(&frame).is_ok(),
        "baseline frame must verify"
    );

    // An adversary on the link replaces a cursor movement with a prosthetic command.
    frame.decoded_output = DecodedOutput::ProstheticControl {
        joints: vec![9.0, 9.0, 9.0],
    };

    assert!(
        verify_signature(&frame).is_err(),
        "NG-T010 REGRESSED: a rewritten command must break the signature"
    );
    assert_eq!(
        verify_neural_frame(&frame).unwrap().verdict,
        Verdict::Rejected,
        "NG-T010 REGRESSED: a tampered command must not be trusted end to end"
    );
}

/// NG-T010 (CLOSED, second half): the provenance commitment covers `decoded_output`, so a
/// tampered frame no longer occupies the same position in the chain as the original.
#[test]
fn ng_t010_commitment_covers_decoded_output() {
    let mut bci = device("t010b");
    let frame = bci.generate_frame().unwrap();
    let original = frame.compute_commitment();

    let mut tampered = frame.clone();
    tampered.decoded_output = DecodedOutput::Command("MALICIOUS".to_string());

    assert_ne!(
        original,
        tampered.compute_commitment(),
        "NG-T010 REGRESSED: commitments must cover decoded_output"
    );
}

/// NG-T006 (CLOSED): the preimage is length-prefixed, so content cannot be shifted between
/// adjacent variable-length fields to produce the same bytes.
///
/// Under the old raw concatenation, a device id of `"ab"` followed by manufacturer `"cd"`
/// encoded identically to `"a"` followed by `"bcd"`, and one signature covered both readings.
#[test]
fn ng_t006_field_boundaries_are_unambiguous() {
    let mut bci = device("t006");
    let base = bci.generate_frame().unwrap();

    let mut left = base.clone();
    left.device_id.id = "ab".to_string();
    left.device_id.manufacturer = "cd".to_string();

    let mut right = base.clone();
    right.device_id.id = "a".to_string();
    right.device_id.manufacturer = "bcd".to_string();

    assert_ne!(
        left.signable_data(),
        right.signable_data(),
        "NG-T006 REGRESSED: a field-boundary shift produced an identical preimage"
    );
}

/// NG-T006 (CLOSED, second half): signature and commitment preimages live in separate
/// namespaces, so bytes built for one purpose cannot be reinterpreted as the other.
#[test]
fn ng_t006_signature_and_commitment_are_domain_separated() {
    let mut bci = device("t006b");
    let frame = bci.generate_frame().unwrap();

    let signable = frame.signable_data();
    let commitment = frame.compute_commitment();

    assert_ne!(
        Sha256::digest(&signable)[..],
        commitment[..],
        "NG-T006 REGRESSED: hashing the signature preimage reproduced the commitment"
    );
}

/// NG-T001: the verifying key is read from the frame, so an unregistered device that signs with a
/// freshly generated key authenticates successfully.
#[test]
fn ng_t001_self_signed_frames_authenticate() {
    let mut impostor = device("definitely-not-your-implant");
    let frame = impostor.generate_frame().unwrap();

    let report = verify_neural_frame(&frame).unwrap();
    assert!(
        report.device_authenticated,
        "NG-T001 FIXED: keys are now registry-bound — update the catalogue and this test"
    );
    assert_eq!(report.verdict, Verdict::Trusted);
}

/// NG-T012 / NG-T005 / NG-T050: registry and policy results are hardcoded in the report.
#[test]
fn ng_t012_registry_checks_are_hardcoded_true() {
    let mut bci = device("t012");
    let frame = bci.generate_frame().unwrap();
    let report = verify_neural_frame(&frame).unwrap();

    assert!(report.firmware_trusted, "NG-T012: not actually checked");
    assert!(report.decoder_approved, "NG-T005: not actually checked");
    assert!(report.model_valid, "NG-T005: not actually checked");
    assert!(
        report.application_authorized,
        "NG-T050: not actually checked"
    );
}

/// NG-T018: nothing examines `timestamp`, so a ten-minute-old frame is accepted.
#[test]
fn ng_t018_stale_frames_are_accepted() {
    let mut simulator = AttackSimulator::new(device("t018"));
    let frames = simulator.run_attack(AttackType::ReplayAttack, 1).unwrap();
    let frame = &frames[0];

    let age = chrono::Utc::now() - frame.timestamp;
    assert!(age.num_minutes() >= 9, "scenario should backdate the frame");
    assert_eq!(
        verify_neural_frame(frame).unwrap().verdict,
        Verdict::Trusted,
        "NG-T018 FIXED: freshness is now enforced — update the catalogue and this test"
    );
}

/// NG-T002: a physiologically impossible signal (the `SignalInjection` scenario emits a constant
/// 999.9 rail) passes verification, because no signal-domain check exists.
#[test]
fn ng_t002_implausible_signals_are_accepted() {
    let mut simulator = AttackSimulator::new(device("t002"));
    let frames = simulator
        .run_attack(AttackType::SignalInjection, 1)
        .unwrap();
    let frame = &frames[0];

    assert!(
        frame.signal_data.iter().all(|s| *s > 900.0),
        "scenario should rail the signal"
    );
    assert_eq!(
        verify_neural_frame(frame).unwrap().verdict,
        Verdict::Trusted,
        "NG-T002 FIXED: a plausibility gate now exists — update the catalogue and this test"
    );
}

/// NG-T015: the chain accepts a frame that branches from a non-tip commitment, and accepts frames
/// with no signature verification at all. Detection is deferred to a whole-chain scan.
#[test]
fn ng_t015_chain_accepts_a_fork() {
    let mut bci = device("t015");
    let mut chain = ProvenanceChain::new();

    let genesis = bci.generate_frame().unwrap();
    let second = bci.generate_frame().unwrap();
    chain.add_frame(&genesis).unwrap();
    chain.add_frame(&second).unwrap();

    // Branch from the genesis commitment rather than the tip.
    let mut fork = second.clone();
    fork.previous_commitment = Some(genesis.compute_commitment());
    fork.signal_data = vec![0.42; 16];

    assert!(
        chain.add_frame(&fork).is_ok(),
        "NG-T015 FIXED: chain now requires tip-only extension — update the catalogue and this test"
    );
    assert!(
        chain.verify_chain().is_err(),
        "the fork is only detectable by a full-chain scan, not at insertion time"
    );
}

/// NG-T053: the blacklist is enforced in `check_capability` but not in `check_output_type` or
/// `check_channel_access`.
#[test]
fn ng_t053_blacklisted_app_still_passes_output_checks() {
    let mut engine = PolicyEngine::new();
    engine.register_policy(PolicyEngine::default_dev_policy("rogue-app".to_string()));
    engine.blacklist_app("rogue-app".to_string());

    assert!(
        engine
            .check_capability("rogue-app", Capability::ReadDecodedOutput)
            .is_err(),
        "capability path does honour the blacklist"
    );

    let cursor = DecodedOutput::CursorPosition { x: 1.0, y: 2.0 };
    assert!(
        engine.check_output_type("rogue-app", &cursor).is_ok(),
        "NG-T053 FIXED: blacklist is now checked on every path — update the catalogue and this test"
    );
}

/// NG-T055: verification failure is reported inside a successful `Result`, so `verify_frame(&f)?`
/// reads as success at the call site.
#[test]
fn ng_t055_rejected_frames_still_return_ok() {
    let mut bci = device("t055");
    let mut frame = bci.generate_frame().unwrap();
    frame.signature = [0u8; 64]; // definitively invalid

    let outcome = neuroguard::verify_frame(&frame);
    assert!(
        outcome.is_ok(),
        "NG-T055 FIXED: verification failure is now an Err — update the catalogue and this test"
    );
    assert_eq!(outcome.unwrap().verdict, Verdict::Rejected);
}

/// NG-T041 / NG-T042: the rate limit and the maximum signal size are declared in policy and read
/// by nobody. This test documents that no API exists to enforce them.
#[test]
fn ng_t041_rate_limits_have_no_enforcement_api() {
    let policy = PolicyEngine::strict_policy("app".to_string(), vec![1]);
    assert_eq!(policy.rate_limit.max_fps, 30);

    let enforcement_sites: usize = [
        "src/policy.rs",
        "src/attestation.rs",
        "src/protocol.rs",
        "src/provenance.rs",
    ]
    .iter()
    .map(|f| {
        fs::read_to_string(repo_path(f))
            .unwrap()
            .matches("rate_limit")
            .count()
    })
    .sum();

    // Every current mention is a declaration or a constructor, never a check.
    assert!(
        enforcement_sites <= 6,
        "NG-T041 may be FIXED: rate_limit is referenced {enforcement_sites} times — check whether \
         enforcement landed and update the catalogue"
    );
}
