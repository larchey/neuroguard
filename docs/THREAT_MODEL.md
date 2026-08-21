# NeuroGuard BCI Threat Model

**Document version:** 1.0
**Date:** 2026-08-21
**Applies to:** NeuroGuard v0.0.1 (`src/{attestation,policy,protocol,provenance,virtual_bci}.rs`)
**Method:** STRIDE per-element, extended with neural-interface-specific vectors
**Status:** Research draft. Findings marked `OPEN` are present in the v0.0.1 code as shipped.

---

## 0. Executive summary

NeuroGuard's v0.0.1 architecture defines the right primitives (device attestation, firmware/model
hash approval, provenance chaining, capability policy) but the *verification pipeline that binds
them together does not yet exist*. Running the shipped attack suite:

```
$ cargo run --example attack_scenarios
Testing attack: ReplayAttack ............ Verdict: Trusted   ⚠️  Attack bypassed verification!
Testing attack: SignalInjection ......... Verdict: Trusted   ⚠️  Attack bypassed verification!
Testing attack: MaliciousDecoder ........ Verdict: Trusted   ⚠️  Attack bypassed verification!
Testing attack: FirmwareDowngrade ....... Verdict: Trusted   ⚠️  Attack bypassed verification!
Testing attack: DeviceImpersonation ..... Verdict: Trusted   ⚠️  Attack bypassed verification!
Testing attack: TamperedCalibration ..... Verdict: Trusted   ⚠️  Attack bypassed verification!
Testing attack: CommandModification ..... Verdict: Trusted   ⚠️  Attack bypassed verification!
Testing attack: DataExfiltration ........ Verdict: Trusted   ⚠️  Attack bypassed verification!
```

**0 of 8 modelled attacks are currently detected.** That is expected for a v0.0.1 prototype, but it
means the README's "Verification Flow" (six ✓ checks) describes an intended design, not the
implemented one. This document is the design that closes that gap.

The five highest-severity findings, all `OPEN`:

| ID | Finding | Why it matters |
|---|---|---|
| [NG-T010](#ng-t010) | `NeuralFrame::signable_data()` does not cover `decoded_output` | The *command* — cursor, prosthetic joint angles, vehicle throttle — is unauthenticated. Anyone on the path can rewrite the intent while the signature still verifies. Highest safety impact in the model. |
| [NG-T001](#ng-t001) | Signature is checked against the public key carried *inside the frame* | Self-signed frames verify. There is no binding to a registry, so "device authenticated" means "the sender owns a key", not "the sender is your implant". |
| [NG-T016](#ng-t016) | No stimulation (write-path) type exists at all | `DecodedOutput` models brain→app only. Closed-loop DBS/sensory feedback — where tampering causes direct physical harm — is outside the protocol's expressive range. |
| [NG-T040](#ng-t040) | No latency/liveness contract on the closed loop | Selective delay/drop of frames in a closed-loop controller is a *safety* attack (oscillation, runaway prosthetic), not just an availability one. Rate limits are declared in `RateLimit` but never enforced anywhere. |
| [NG-T050](#ng-t050) | `PolicyEngine` has no enforcement point | `check_capability`/`check_channel_access`/`check_output_type` are never called by `verify_frame` or any pipeline. Policy is advisory; every app effectively holds every capability. |

Remediation is sequenced in [§9](#9-remediation-roadmap). The protocol changes ([§9.1](#91-v010--protocol-hardening-breaking))
are breaking and should land before any hardware integration.

---

## 1. Scope and method

### 1.1 What this model covers

The full neural data path from electrode to actuator, and the reverse path from application to
stimulator, for a NeuroGuard-mediated BCI:

- Implanted or wearable acquisition hardware and its firmware
- The wireless/wired telemetry link
- Signal conditioning, feature extraction, and decoder inference
- NeuroGuard middleware (attestation, provenance, policy)
- Consuming applications (cursor, speech synthesis, prosthetic, wheelchair, vehicle)
- The stimulation/feedback return path (currently unmodelled in code — see [NG-T016](#ng-t016))
- Supporting flows: calibration, firmware update, decoder model update, policy administration

### 1.2 What this model excludes

Out of scope, stated explicitly so the boundary is auditable:

- **Surgical and physical-access attacks** on the implant itself (explantation, direct probe
  attachment). Assumed to require adversary capability far exceeding the modelled attackers, and
  addressed by clinical rather than software controls.
- **Attacks on the human** — coercion, social engineering of the user, sensory illusions delivered
  through legitimate channels.
- **Full RF-layer analysis** (modulation, jamming resistance, near-field key agreement). We model
  the *effects* of RF interference ([NG-T047](#ng-t047)) but not radio design.
- **Neuroscientific validity** of decoders. A decoder that is simply *wrong* is a safety hazard, but
  a quality problem, not a security one — except where an adversary induces the error
  ([NG-T013](#ng-t013)).
- **Regulatory sufficiency.** [§10](#10-standards-alignment) maps to standards but this is not a
  submission-grade risk file.

### 1.3 Method

STRIDE per-element over the DFD in [§3](#3-data-flow-and-trust-boundaries), then a second pass for
vectors that generic STRIDE does not surface because they have no analogue in conventional IT
systems ([§5](#5-bci-specific-vector-deep-dives)):

1. **Neural signal spoofing** — synthetic or replayed neural activity accepted as genuine intent
2. **Stimulation tampering** — modification of energy delivered *into* tissue
3. **Feedback-loop DoS** — attacks on timing/liveness of a closed loop, where degradation is harm
4. **Side-channel neural data leakage** — inference of neural content from metadata, timing, or
   from data the application is legitimately permitted to see

For each threat: attacker, precondition, mechanism, impact, current status in code, detection
signal, and mitigation. Threats are catalogued machine-readably in
[`threat-catalog.json`](threat-catalog.json), which `tests/threat_model.rs` keeps in sync with this
document and with the `AttackType` enum.

### 1.4 Risk rubric

Conventional CIA severity understates BCI risk: an availability failure in a wheelchair controller
is a physical-harm event, and a confidentiality failure is irreversible (you cannot rotate a brain).
Impact is therefore scored in three dimensions and severity takes the worst:

| Score | Safety (S) | Privacy (P) | Function (F) |
|---|---|---|---|
| 4 | Life-threatening or permanent injury | Irrevocable disclosure of protected mental content (inner speech, health state, identity-linkable neural signature) | Total, unrecoverable loss of assistive function |
| 3 | Injury requiring intervention | Disclosure of decoded intent history | Loss of function during a critical task |
| 2 | Transient harm, no intervention | Behavioural/session metadata | Degraded function |
| 1 | Discomfort | Non-linkable aggregates | Nuisance |
| 0 | None | None | None |

Likelihood L1 (requires nation-state capability + physical access) … L5 (trivially reachable by any
app on the host today).

**Severity = f(max(S,P,F), L)**, with any S≥3 finding floored at High and any S=4 with L≥3 floored
at Critical.

### 1.5 Attacker profiles

| Profile | Capability | Position | Typical threats |
|---|---|---|---|
| **A1 — Malicious application** | Ordinary code running on the host, registered with NeuroGuard | Inside the app boundary | [NG-T003](#ng-t003), [NG-T030](#ng-t030), [NG-T034](#ng-t034), [NG-T050](#ng-t050), [NG-T052](#ng-t052) |
| **A2 — Network/link adversary** | Passive sniff and active modification of telemetry | On the wireless link or host IPC | [NG-T010](#ng-t010), [NG-T011](#ng-t011), [NG-T018](#ng-t018), [NG-T031](#ng-t031), [NG-T040](#ng-t040) |
| **A3 — Compromised host** | Code execution in the NeuroGuard process or OS | Inside the middleware boundary | Most of the catalogue; bounded only by hardware root of trust |
| **A4 — Supply chain** | Controls a firmware image, decoder model, or dependency | Upstream of deployment | [NG-T012](#ng-t012), [NG-T013](#ng-t013), [NG-T014](#ng-t014) |
| **A5 — Insider / rogue clinician** | Legitimate credentials for calibration or policy admin | Inside the admin boundary | [NG-T004](#ng-t004), [NG-T017](#ng-t017), [NG-T022](#ng-t022) |
| **A6 — Proximate RF adversary** | Radio transmit/receive near the user | Physical proximity | [NG-T002](#ng-t002), [NG-T037](#ng-t037), [NG-T046](#ng-t046), [NG-T047](#ng-t047) |
| **A7 — Curious data holder** | Lawful custody of stored neural data | Post-hoc | [NG-T034](#ng-t034), [NG-T035](#ng-t035) |

---

## 2. Assets

Ranked by consequence of compromise, not by how much code touches them.

| Asset | Compromise means | Recoverable? |
|---|---|---|
| **Physical safety of the user** | Injury via actuator or stimulation | No |
| **Integrity of intent** — that an executed command reflects what the user meant | Actions attributed to the user that they did not will | No (medico-legally toxic) |
| **Raw neural signal** | Discloses health status, cognitive/affective state, and a re-identifiable neural fingerprint | No — not rotatable |
| **Decoded output history** | Behavioural profile, attempted speech including unsent inner speech | No |
| **Availability of assistive function** | User loses mobility/communication | Yes, but harm accrues during outage |
| **Device signing key** | Full impersonation of the implant | Only by key rotation, which implants may not support |
| **Decoder model** | Both IP and an attack surface ([NG-T013](#ng-t013)) | Yes |
| **Calibration parameters** | Subtle, persistent intent corruption | Yes |
| **Provenance chain** | Loss of forensic accountability | No, retroactively |
| **Stimulation parameter set** | Direct physical harm channel | No |

---

## 3. Data flow and trust boundaries

### 3.1 DFD

```
                            ┌──────────────── TB-5: person ────────────────┐
                            │                                              │
   ┌────────────────────────┴───────────────────────────────────────┐      │
   │                        NEURAL TISSUE                           │      │
   └───▲──────────────────────────────────────────────┬────────────┘      │
       │ (stim energy)                                 │ (action potentials)│
       │                                               ▼                    │
┌──────┴─────────────┐                        ┌────────────────────┐        │
│ E8 Stimulator      │                        │ E1 Electrode array │        │
│  (write path)      │                        │  + analog frontend │        │
└──────▲─────────────┘                        └─────────┬──────────┘        │
       │ DF-8 stim command                              │ DF-1 raw samples  │
       │                                                ▼                    │
       │                              ┌────────────────────────────┐         │
       │                              │ E2 Implant firmware / DSP  │  TB-1   │
       │                              │  - filtering, framing      │◄────────┤ device
       │                              │  - Ed25519 signing         │         │ boundary
       │                              └─────────┬──────────────────┘         │
       │                                        │ DF-2 NeuralFrame           │
       │                                        ▼                            │
       │   ═══════════════ TB-2: telemetry link (RF / USB / IPC) ═══════════ │
       │                                        │                            │
       │                                        ▼                            │
       │                              ┌────────────────────────────┐         │
       │                              │ E3 Signal gateway          │         │
       │                              │  - deserialize, admit      │         │
       │                              └─────────┬──────────────────┘         │
       │                                        │ DF-3                       │
       │                                        ▼                            │
       │        ┌────────────────────────────────────────────────┐           │
       │        │ E4 NeuroGuard middleware              TB-3     │           │
       │        │   attestation::verify_neural_frame()           │           │
       │        │   provenance::ProvenanceChain                  │           │
       │        │   policy::PolicyEngine                         │           │
       │        │   [MISSING] rate limiter, freshness, registry  │           │
       │        └───▲────────────┬──────────────────┬────────────┘           │
       │            │ DF-6       │ DF-4 decoded     │ DF-5 raw (privileged)  │
       │            │ policy     ▼                  ▼                        │
       │            │   ┌──────────────────┐  ┌──────────────────┐           │
       │            │   │ E5 Application   │  │ E6 Recorder /    │  TB-4     │
       │            │   │  cursor, speech, │  │    research store│◄──────────┘
       │            │   │  prosthetic, veh.│  └──────────────────┘   app boundary
       │            │   └────────┬─────────┘
       │            │            │ DF-7 actuation
       │            │            ▼
       │            │   ┌──────────────────┐
       └────────────┼───┤ E7 Actuator      │
        stim/feedback│   │  arm, chair, TTS │
                     │   └──────────────────┘
                     │
            ┌────────┴──────────┐
            │ E9 Admin plane    │  registry, firmware/model approval,
            │  (clinician, OEM) │  calibration, policy authoring
            └───────────────────┘
```

### 3.2 Trust boundaries

| ID | Boundary | Crossing flows | Current enforcement | Gap |
|---|---|---|---|---|
| **TB-1** | Tissue/hardware → firmware | DF-1, DF-8 | None. Signal is trusted the moment it is sampled. | Signing happens *after* any upstream compromise — a firmware-level or analog-level injection produces a validly signed lie ([NG-T002](#ng-t002)). |
| **TB-2** | Device → host, across the link | DF-2 | Ed25519 signature over *part* of the frame | No confidentiality ([NG-T037](#ng-t037)), no freshness ([NG-T018](#ng-t018)), no coverage of `decoded_output` ([NG-T010](#ng-t010)) |
| **TB-3** | Gateway → middleware | DF-3 | `verify_neural_frame` | Registry checks are hardcoded `true`; verdict is advisory ([NG-T012](#ng-t012), [NG-T056](#ng-t056)) |
| **TB-4** | Middleware → application | DF-4, DF-5 | `PolicyEngine` (defined) | Never invoked ([NG-T050](#ng-t050)); blacklist not checked on all paths ([NG-T053](#ng-t053)) |
| **TB-5** | System → person | DF-7, DF-8 | None | No dose/rate/range limiter, no hardware interlock, no failsafe contract ([NG-T016](#ng-t016), [NG-T044](#ng-t044)) |
| **TB-6** | Admin plane → middleware | policy/firmware/model/calibration updates | None | No authenticated admin channel, no signed policy, no audit ([NG-T004](#ng-t004), [NG-T022](#ng-t022)) |

TB-5 is the boundary that distinguishes this from an ordinary IT threat model: it is the only one
where a policy decision converts directly into physical force or electrical charge in a person, and
it is currently the least defended.

### 3.3 STRIDE per element

`●` = applicable and open, `◐` = partially mitigated, `○` = applicable, mitigated by design, `–` = not applicable.

| Element | S | T | R | I | D | E | Leading threats |
|---|:-:|:-:|:-:|:-:|:-:|:-:|---|
| E1 Electrode/frontend | ● | ● | – | ● | ● | – | T002, T031, T047 |
| E2 Implant firmware | ● | ● | ● | ● | ● | ● | T001, T012, T046 |
| DF-2 telemetry (TB-2) | ● | ● | ● | ● | ● | – | T010, T011, T018, T037 |
| E3 Signal gateway | ◐ | ● | ● | ● | ● | ● | T042, T043, T045 |
| E4 NeuroGuard middleware | ● | ● | ● | ● | ● | ● | T015, T050, T032 |
| DF-4/5 app flows (TB-4) | ● | ● | ● | ● | ● | ● | T030, T034, T051 |
| E5 Application | ● | ● | ● | ● | ● | ● | T003, T036, T052 |
| E7 Actuator / E8 Stimulator (TB-5) | ● | ● | ● | – | ● | ● | T016, T017, T040, T044 |
| E9 Admin plane (TB-6) | ● | ● | ● | ● | ● | ● | T004, T013, T022 |
| Provenance store | – | ● | ● | ● | ● | – | T015, T021, T035 |

Every element scores `●` on Elevation except the pure-hardware ones — a direct consequence of
[NG-T050](#ng-t050): with no enforcement point, there is no privilege to elevate *from*.

---

## 4. Threat catalogue

Format: **STRIDE** · **element** · **attacker profile** · **impact (S/P/F)** · **likelihood** →
**severity** · **status**. `OPEN` = exploitable in v0.0.1 as shipped. `PARTIAL` = a control exists
but is incomplete or unenforced. `DESIGN` = the threat is real but the corresponding subsystem does
not exist yet, so there is nothing to fix — there is something to build.

### 4.1 Spoofing

#### <a id="ng-t001"></a>NG-T001 — Implant impersonation via self-asserted public key
**S** · E2/TB-2 · A2, A3 · S4 P3 F3 · L4 → **Critical** · `OPEN`

`verify_signature` (`src/attestation.rs:167`) loads the verifying key from
`frame.device_id.public_key` — a field the frame itself carries. Any party able to construct a frame
generates a keypair, signs, and passes authentication. `DeviceRegistry` exists
(`src/attestation.rs:51`) but `verify_neural_frame` never consults it, which is why the
`DeviceImpersonation` scenario returns `Trusted`.

*Mitigation:* verification must take the registry as an input and resolve the key by `device_id.id`,
rejecting frames whose embedded key does not equal the registered one; the embedded key field should
be removed from the wire format entirely to make the mistake unrepresentable. Long-term: bind device
identity to a hardware root of trust (attestation certificate chained to an OEM CA, per-device
keypair generated in secure element, key never leaves the implant).

#### <a id="ng-t002"></a>NG-T002 — Neural signal spoofing at or below the signing boundary
**S/T** · E1, E2/TB-1 · A4, A6, A3-on-implant · S4 P0 F4 · L2 → **High** · `DESIGN`

Signing happens *after* acquisition (`src/virtual_bci.rs:181`). Anything that corrupts the signal
before that point — induced currents on the electrode leads, a firmware implant, a compromised DSP
stage — yields a cryptographically perfect frame containing fabricated intent. Cryptography cannot
reach below TB-1; only signal-domain plausibility can. See [§5.1](#51-neural-signal-spoofing).

#### <a id="ng-t003"></a>NG-T003 — Application identity spoofing
**S** · E5/TB-4 · A1, A3 · S3 P4 F2 · L5 → **High** · `OPEN`

`app_id` is an unauthenticated `String` (`src/policy.rs:21`). Any caller claiming
`"clinical-prosthetic-controller"` inherits its policy, including `ControlDevice`. There is no app
attestation, no binding to an OS-level identity (uid, code signature, container identity), and no
session establishment.

*Mitigation:* app identity must be established out of band — OS peer credentials on the IPC socket,
code-signing identity, or an attested token — and the policy key must be that verified identity, not
a self-declared string.

#### <a id="ng-t004"></a>NG-T004 — Admin/clinician plane spoofing
**S/E** · E9/TB-6 · A5, A3 · S4 P4 F4 · L3 → **Critical** · `DESIGN`

`register_device`, `approve_firmware`, `approve_model`, `register_policy`, and `blacklist_app` are
plain `&mut self` methods with no authentication, authorisation, or audit. Whoever reaches the
process reaches the root of trust. Calibration and threshold updates ([NG-T017](#ng-t017)) ride the
same unprotected plane.

*Mitigation:* signed administrative operations (approval bundles signed by an OEM/clinic key,
verified against a pinned trust anchor), two-person rule for changes affecting stimulation limits,
append-only audit of every admin mutation.

#### <a id="ng-t005"></a>NG-T005 — Decoder/transform impersonation
**S/T** · E4 · A3, A4 · S3 P2 F3 · L4 → **High** · `PARTIAL`

`transformation_hash` and `model_hash` are self-asserted values inside the frame. `verify_model`
exists but is never called, and nothing binds a hash to an *attested* execution — a compromised
decoder can advertise the approved model hash while running different weights. Hash-of-artifact
proves what was *claimed*, not what was *executed*.

*Mitigation:* short term, wire `verify_model`/`verify_firmware` into the pipeline (they are already
written). Medium term, measure the loaded model at load time inside an enclave/TEE and report a
measurement, not a claim.

#### <a id="ng-t006"></a>NG-T006 — Signature transplantation via ambiguous serialisation
**S/T** · TB-2 · A2 · S3 P1 F2 · L2 → **Medium** · `OPEN`

`signable_data` (`src/protocol.rs:158`) concatenates a variable-length `device_id.id` with
fixed-width fields and a variable-length sample vector, with no length prefixes and no domain
separator. Distinct frames can therefore serialise to identical byte strings — e.g. a shift of one
byte between the tail of `id` and the head of `firmware_hash` — so a signature valid for one
(device, firmware) pair can be valid for another. `manufacturer` and `model` are omitted from the
signed data entirely while `verify_firmware` keys its approved-hash lookup on `model`
(`src/attestation.rs:123`), giving a cross-model confusion attack: flip `model` to a device family
whose approved list contains the attacker's firmware hash, and the signature still verifies.

*Mitigation:* sign a canonical, length-prefixed encoding of the *entire* frame with a domain
separation tag (`"neuroguard-frame-v1"`), including `manufacturer`, `model`, sequence number, and
`decoded_output`.

### 4.2 Tampering

#### <a id="ng-t010"></a>NG-T010 — Decoded output is not covered by the signature
**T** · TB-2, E3, E4 · A2, A3 · S4 P0 F4 · L4 → **Critical** · `OPEN`

`signable_data` covers `device_id.id`, `firmware_hash`, `timestamp`, `transformation_hash`,
`model_hash`, `previous_commitment`, and `signal_data` — but **not `decoded_output`**
(`src/protocol.rs:158-155`). `compute_commitment` has the same omission
(`src/protocol.rs:135-135`), so the provenance chain does not cover it either. The one field that
determines what physically happens — `ProstheticControl { joints }`, `VehicleControl { throttle,
steering, brake }`, `Text` — can be rewritten in flight with the signature and the entire provenance
chain remaining valid. This is why the `CommandModification` scenario, which injects
`"MALICIOUS_COMMAND"`, verifies as `Trusted`.

*Mitigation:* include `decoded_output` in both `signable_data()` and `compute_commitment()`. Where
decoding happens off-device, the decoder must be a distinct signing principal, producing a second
signature that binds decoder output to the input frame commitment — so the chain reads
`device signs samples → decoder signs (commitment, output)`, and neither can be substituted alone.

#### <a id="ng-t011"></a>NG-T011 — Signal tampering in transit
**T** · TB-2 · A2, A6 · S4 P0 F4 · L3 → **High** · `PARTIAL`

Sample data *is* signed, so modification is detectable once [NG-T001](#ng-t001) is fixed — until
then, an active adversary re-signs with its own key and nothing notices. Additionally, without
encryption ([NG-T037](#ng-t037)) an adversary can craft modifications that are semantically
plausible because it can read the plaintext it is modifying.

#### <a id="ng-t012"></a>NG-T012 — Firmware downgrade / rollback
**T/E** · E2 · A4, A3, A5 · S4 P2 F3 · L3 → **High** · `PARTIAL`

`verify_firmware` (`src/attestation.rs:123`) is implemented but unreachable from
`verify_neural_frame`, which sets `report.firmware_trusted = true` unconditionally
(`src/attestation.rs:222`). Approved-hash lists are also append-only with no revocation and no
monotonic version, so a *previously approved but now vulnerable* image stays valid forever — the
classic rollback gap. `FirmwareDowngrade` returns `Trusted` today.

*Mitigation:* pass a registry into verification; add a monotonic security version number per image
with anti-rollback enforcement (reject SVN < the highest ever observed for that device); support
revocation of approved hashes with a signed revocation list.

#### <a id="ng-t013"></a>NG-T013 — Decoder model poisoning and swap
**T** · E4, E9 · A4, A5 · S4 P2 F4 · L2 → **High** · `PARTIAL`

Two distinct attacks share one control. *Swap*: substituting a different model, addressed by
[NG-T005](#ng-t005). *Poisoning*: the approved model is itself trained to misbehave — a backdoor
that maps a specific, attacker-inducible neural pattern (or an artefact injectable over the
electrode, cf. [NG-T002](#ng-t002)) to a chosen output, while behaving normally otherwise. A hash
check cannot detect poisoning; the hash of a backdoored model is a perfectly valid hash.

*Mitigation:* provenance for the *training* pipeline (dataset commitment, training-run attestation),
independent behavioural acceptance testing before approval, and runtime output plausibility
monitoring ([§5.1](#51-neural-signal-spoofing)) as the only defence that survives a poisoned model.

#### <a id="ng-t014"></a>NG-T014 — Calibration and transformation tampering
**T** · E2, E4, E9 · A5, A3 · S3 P1 F4 · L3 → **High** · `PARTIAL`

Calibration is where a subtle attack lives: a small bias in the transform shifts decoded intent
persistently, degrades slowly, and is easily mistaken for signal drift or disease progression.
`Transformation`/`TransformType` model this well (`src/provenance.rs:39-64`), but
`transformation_hash` is never verified against an approved set and `ProvenanceChain::add_frame`
hardcodes `TransformType::Decoding` (`src/provenance.rs:102`), discarding the real transform type —
so the chain records a transformation history it did not actually observe.

*Mitigation:* verify `transformation_hash` against approved transforms; record the actual transform
chain rather than a hardcoded value; require re-attestation and user-visible notification on
calibration change; retain the previous calibration for rollback and A/B comparison.

#### <a id="ng-t015"></a>NG-T015 — Provenance chain forking and replay insertion
**T/R** · Provenance store · A2, A3 · S2 P0 F2 · L3 → **Medium** · `OPEN`

`add_frame` accepts any frame whose `previous_commitment` exists *anywhere* in the index, not just at
the chain tip (`src/provenance.rs:87`). An adversary can branch from an arbitrary historical
commitment, and a replayed mid-stream frame is appended without complaint. `verify_chain` only
notices because it assumes strict adjacency (`chain[i-1]`), which means it *also* rejects any
legitimate out-of-order or gapped delivery — see [NG-T045](#ng-t045). Detection is deferred to a
whole-chain scan and cannot distinguish attack from packet loss.

Additionally, `compute_commitment` hashes `timestamp.timestamp()` — whole seconds — so two frames in
the same second with identical samples produce identical commitments, colliding in
`commitment_index` and silently corrupting history lookups.

*Mitigation:* require `previous_commitment == tip`; add a strictly monotonic per-device sequence
number to the frame and to the commitment; include sub-second precision or a nonce; reject duplicate
commitments outright rather than overwriting the index entry.

#### <a id="ng-t016"></a>NG-T016 — Stimulation parameter tampering
**T/E** · E8/TB-5 · A1, A2, A3 · S4 P0 F4 · L3 → **Critical** · `DESIGN`

There is no write path in the protocol. `DecodedOutput` models brain→application only; nothing in
v0.0.1 describes charge, amplitude, pulse width, frequency, duty cycle, or duration, and therefore
nothing constrains them. Any BCI that closes the loop — DBS, sensory feedback, cortical stimulation
for prosthetic sensation — currently has its highest-consequence data flow entirely outside
NeuroGuard's coverage. See [§5.2](#52-stimulation-tampering).

#### <a id="ng-t017"></a>NG-T017 — Closed-loop trigger threshold tampering
**T** · E4, E9 · A5, A3 · S4 P1 F3 · L2 → **High** · `DESIGN`

Adaptive stimulation systems fire when a biomarker crosses a threshold. Moving the threshold is a
lower-noise attack than commanding stimulation directly: it produces over-stimulation or complete
therapeutic failure while every individual command remains within approved limits and looks
clinically normal. This is the parameter-level analogue of [NG-T014](#ng-t014) and needs the same
treatment plus explicit clinical bounds.

#### <a id="ng-t018"></a>NG-T018 — Timestamp manipulation and absent freshness check
**T/S** · TB-2, E4 · A2 · S3 P0 F3 · L4 → **High** · `OPEN`

Nothing in the verification path examines `frame.timestamp`. The `ReplayAttack` scenario backdates a
frame by ten minutes and is still `Trusted`. Timestamps are also second-granular and derived from an
unsynchronised device clock, so they cannot carry freshness on their own.

*Mitigation:* freshness must come from a sequence number plus a receiver-side acceptance window
(reject frames outside ±N ms of local time after clock sync, and reject any sequence number ≤ the
last accepted one). For safety-critical outputs, add a challenge–response nonce so liveness is proven
rather than asserted.

### 4.3 Repudiation

#### <a id="ng-t020"></a>NG-T020 — Intent is not attributable
**R** · TB-5, E4 · all · S3 P2 F1 · L4 → **High** · `DESIGN`

When a BCI-driven arm injures someone, three answers must be distinguishable: the user intended it,
the decoder erred, or an attacker injected it. v0.0.1 cannot separate these — the output is not
signed ([NG-T010](#ng-t010)), the chain is in-memory only ([NG-T021](#ng-t021)), and no confidence or
provenance metadata accompanies a command. Note the inverse risk: a system that logs everything
attributably becomes a surveillance record of a person's intentions, so the design must bound what
is retained ([NG-T034](#ng-t034)).

*Mitigation:* sign outputs, persist a tamper-evident log with periodic external anchoring, record
decoder confidence and the acting policy version alongside each safety-relevant command, and define a
retention policy that keeps the *attestation* (hash, signature, metadata) far longer than the *neural
content*.

#### <a id="ng-t021"></a>NG-T021 — Provenance is volatile and unanchored
**R/T** · Provenance store · A3 · S1 P0 F1 · L4 → **Medium** · `OPEN`

`ProvenanceChain` is an in-process `Vec` + `HashMap` (`src/provenance.rs:10-17`) with no persistence,
no signature over the chain state, and no external anchor. A process restart erases history; an
attacker with process access rewrites it freely, since links are recomputed from frames rather than
signed as a log.

*Mitigation:* append-only persistent log, per-link signature or MAC under a key not held by the
writer, periodic anchoring of the head commitment to an external witness (clinic server, transparency
log), and a bounded-memory representation ([NG-T042](#ng-t042)).

#### <a id="ng-t022"></a>NG-T022 — Administrative and policy changes are unlogged
**R** · E9/TB-6 · A5 · S3 P3 F2 · L4 → **High** · `DESIGN`

No record exists of who approved a firmware hash, blacklisted an app, widened a capability set, or
changed a stimulation limit. Post-incident, the security-relevant configuration history is
unreconstructible.

*Mitigation:* every admin mutation becomes a signed, logged event carrying actor identity, previous
and new value, and justification; policy state is content-addressed so a running system can report
exactly which policy version authorised a given command.

### 4.4 Information disclosure

#### <a id="ng-t030"></a>NG-T030 — Raw neural exfiltration by an over-permissioned application
**I** · DF-5/TB-4 · A1 · S0 P4 F0 · L5 → **High** · `OPEN`

`Capability::ReadRawSignal` and `RecordData` are defined but never checked, and every
`NeuralFrame` carries `signal_data` regardless of the recipient's capabilities
(`src/protocol.rs:30`). An application that only needs a cursor position receives the underlying
neural samples in the same struct. This is the BCI equivalent of shipping the raw camera feed to an
app that asked for a QR code — and unlike a camera feed, the user cannot change their brain after a
leak. The `DataExfiltration` scenario is undetected because there is nothing to detect: the data is
handed over legitimately.

*Mitigation:* the frame delivered across TB-4 must be *projected* per policy — raw samples stripped
unless `ReadRawSignal` is held, with the provenance chain able to attest to the projection
(transform-of-transform), so an app can verify data authenticity without receiving more than it is
entitled to. This is the "neural data firewall" the project's thesis calls for and is the single
highest-value privacy control.

#### <a id="ng-t031"></a>NG-T031 — Traffic-analysis side channel on frame size and cadence
**I** · TB-2 · A2, A6 · S0 P3 F0 · L3 → **Medium** · `DESIGN`

Frame length is a direct function of `signal_data.len()`, and inter-frame timing tracks the
acquisition and decode pipeline. An adversary who cannot decrypt anything still observes *when* the
user is generating decodable intent, at what rate, and — through burst structure — coarse
correlates of attention, motor activity, or seizure events. Encryption alone does not close this.

*Mitigation:* constant-size frames with padding to a fixed bucket, constant-rate transmission
(send padding frames during idle), and jittered scheduling for non-latency-critical flows. Note the
direct tension with [NG-T046](#ng-t046) (energy) and [§5.3](#53-feedback-loop-dos) (latency budget) —
constant-rate telemetry costs implant battery and adds jitter, so it should be selectable per
deployment rather than always-on. See [§5.4](#54-side-channel-neural-data-leakage).

#### <a id="ng-t032"></a>NG-T032 — Verification errors leak policy and registry contents
**I** · E4 · A1 · S0 P2 F0 · L5 → **Medium** · `OPEN`

Error variants are highly descriptive: `FirmwareMismatch` reports `"{n} approved hashes"` and echoes
the submitted hash (`src/attestation.rs:133-138`), `PolicyViolation` reports `"channel {id} not in
whitelist"` (`src/policy.rs:188`), and `ApplicationUnauthorized` distinguishes "no policy for X" from
"blacklisted" (`src/policy.rs:152-166`). An unprivileged app can therefore enumerate the channel
whitelist, the capability set, the size of approval lists, and its own blacklist status — a
probing oracle for planning a real attack.

*Mitigation:* two-tier errors — a coarse, stable variant returned across the trust boundary
(`Denied`), and the detailed variant retained in the internal audit log only. Detail level should be
a build/deployment setting, verbose in the dev SDK, terse in production.

#### <a id="ng-t033"></a>NG-T033 — Timing side channels in verification and decode
**I** · E4 · A1, A3 · S0 P2 F0 · L2 → **Low** · `OPEN`

`verify_firmware`/`verify_model` use linear `Vec::contains` over approved hashes
(`src/attestation.rs:132`, `src/attestation.rs:149`), and the policy path short-circuits on the first
failing check. The approved hashes are not secrets, so the classic key-recovery framing does not
apply, but *ordering and membership* leak, and — more interestingly for BCI — decode latency
correlates with signal properties, which is a channel into the neural content itself.

*Mitigation:* constant-time comparison where the compared value is secret; fixed-order,
non-short-circuiting policy evaluation; constant-latency decode scheduling (fixed deadline, emit at
deadline regardless of when the answer is ready), which also serves [§5.3](#53-feedback-loop-dos).

#### <a id="ng-t034"></a>NG-T034 — Inference of protected attributes from permitted data
**I** · E5, E6, A7 · A1, A7 · S0 P4 F0 · L4 → **High** · `DESIGN`

The deepest privacy problem in BCI is not exfiltration — it is that data an application is
*legitimately* entitled to still discloses far more than the user consented to. Cursor-decode
features can carry correlates of fatigue, affect, cognitive load, medication state, and seizure
susceptibility; a neural response pattern is stable enough over time to function as a biometric
identifier, so "anonymised" neural data is re-identifiable in a way anonymised text is not.
Capability-based access control cannot express "you may use this signal for cursor control but not to
infer my mood".

*Mitigation:* purpose limitation as a first-class policy dimension alongside capability — declared
purpose, enforced retention limits, and *transformation* policies that deliver the narrowest
sufficient representation (decoded output only; features band-limited to the task; noise added where
the task tolerates it). Where enforcement is impossible in software, contractual and regulatory
controls must be named as the mitigation rather than pretending a technical one exists. This is
NeuroGuard's most defensible research contribution and the least solved.

#### <a id="ng-t035"></a>NG-T035 — Commitment hashes as a content-confirmation oracle
**I** · Provenance store · A7 · S0 P3 F0 · L2 → **Medium** · `OPEN`

`compute_commitment` is an unkeyed SHA-256 over the sample vector and metadata
(`src/protocol.rs:135`). Published or shared commitments (the point of external anchoring, cf.
[NG-T021](#ng-t021)) let anyone holding candidate neural data confirm an exact match — a
low-entropy-preimage confirmation attack. Short windows, quantised samples, and stereotyped activity
make candidate enumeration realistic for targeted content.

*Mitigation:* commit with a keyed construction (HMAC-SHA-256) or include a per-frame random salt
carried in the frame, so commitments are hiding as well as binding.

#### <a id="ng-t036"></a>NG-T036 — Unintended speech disclosure
**I** · E5, TB-5 · A1 · S1 P4 F1 · L3 → **High** · `DESIGN`

`DecodedOutput::Text` for speech neuroprosthetics has no notion of *intent to utter*. Attempted
speech, inner speech, and rehearsed-but-rejected phrases can all decode. Publishing everything the
decoder produces makes the user's unspoken thought a wire protocol.

*Mitigation:* an explicit go/no-go gating signal (user-controlled utterance trigger), a hold-and-
confirm buffer for anything above a sensitivity threshold, and content policy applied *before*
synthesis. The user must be able to unsend, and the default must be not-yet-sent.

#### <a id="ng-t037"></a>NG-T037 — Plaintext telemetry
**I** · TB-2 · A2, A6 · S1 P4 F0 · L4 → **High** · `OPEN`

`GlobalRestrictions::require_encryption` defaults to `true` (`src/policy.rs:138`) but is read
nowhere. The protocol has no session establishment, no key agreement, and no AEAD — frames are
signed plaintext. Anyone on the link reads raw neural samples.

*Mitigation:* authenticated encryption for all telemetry with forward secrecy, keys bound to the
attested device identity; enforce `require_encryption` at admission rather than storing it as an
unread field.

### 4.5 Denial of service

#### <a id="ng-t040"></a>NG-T040 — Feedback-loop DoS
**D** · TB-2, E4, TB-5 · A2, A3 · S4 P0 F4 · L3 → **Critical** · `DESIGN`

Selective delay, drop, or reordering of frames in a closed control loop is not merely an outage: a
controller tuned for a fixed latency becomes unstable when latency changes, producing oscillation,
overshoot, or a runaway actuator. There is no latency budget, deadline, staleness check, or liveness
contract anywhere in v0.0.1. See [§5.3](#53-feedback-loop-dos).

#### <a id="ng-t041"></a>NG-T041 — Frame flooding with no rate limiting
**D** · E3, E4 · A1, A2 · S3 P0 F4 · L5 → **High** · `OPEN`

`RateLimit { max_fps, max_bytes_per_sec }` is defined (`src/policy.rs:85-92`) and populated by both
`default_dev_policy` and `strict_policy`, but no code in the crate reads it. There is no token
bucket, no counter, no clock. A flood starves the legitimate control path — which, per
[NG-T040](#ng-t040), is a safety event.

#### <a id="ng-t042"></a>NG-T042 — Unbounded memory growth
**D** · E3, Provenance store · A1, A2 · S3 P0 F4 · L4 → **High** · `OPEN`

`signal_data: Vec<f32>` has no size limit on deserialisation; `GlobalRestrictions::max_signal_size`
(`src/policy.rs:119`) is never checked. `ProvenanceChain` grows without bound — at 1 kHz acquisition
its `Vec` plus `HashMap` index grow monotonically for the lifetime of the process, an availability
failure that arrives on its own without any attacker.

*Mitigation:* enforce `max_signal_size` at the deserialisation boundary before allocation; make the
chain a bounded window with older links compacted into a checkpoint commitment.

#### <a id="ng-t043"></a>NG-T043 — Verification-cost amplification
**D** · E3, E4 · A1, A2 · S3 P0 F3 · L4 → **High** · `OPEN`

Per-frame cost is one Ed25519 verification plus SHA-256 over the whole sample vector, computed
twice (`signable_data` builds a fresh `Vec<u8>` copy of every sample; `compute_commitment` hashes
them again). Cheap for the attacker to send, expensive to reject. On an embedded gateway this is the
practical DoS.

*Mitigation:* check the cheap invariants first (size cap, sequence window, device known, rate
budget), verify signatures last; hash incrementally without the intermediate copy; account crypto
work against the sender's rate budget.

#### <a id="ng-t044"></a>NG-T044 — Fail-secure/fail-safe conflict
**D** · TB-5 · any · S4 P0 F4 · L4 → **Critical** · `DESIGN`

The README states "fail-secure defaults — deny-by-default". For a wheelchair mid-crossing or a
prosthetic hand holding a hot pan, denying is not safe. Conversely, "fail-open" on a stimulator is
unacceptable. The correct behaviour is neither: it is a *defined degraded mode* per output type, and
no such definition currently exists.

*Mitigation:* a per-`OutputType` failure policy — cursor: freeze; prosthetic: hold current pose, then
controlled release; wheelchair: controlled stop, not a hard stop; vehicle: hand back to a fallback
controller; stimulation: ramp to zero, never abrupt cessation where withdrawal effects exist. Each
policy must be authored with clinical input and be part of the approved configuration.

#### <a id="ng-t045"></a>NG-T045 — Provenance-chain wedge (self-inflicted DoS)
**D** · E4 · A2, or plain packet loss · S3 P0 F4 · L4 → **High** · `OPEN`

`add_frame` rejects any frame whose predecessor is unknown (`src/provenance.rs:87`), and
`verify_chain` requires strict adjacency (`src/provenance.rs:137`). One lost frame on a lossy RF
link therefore invalidates the entire subsequent stream. An adversary who can drop a single packet
achieves a persistent denial; ordinary interference achieves it by accident.

*Mitigation:* tolerate gaps explicitly — sequence numbers with a bounded reorder/loss window, gap
events recorded in the chain as first-class `Gap` links (preserving the evidence that data is
missing) rather than treated as chain destruction, and resynchronisation via a signed checkpoint.

#### <a id="ng-t046"></a>NG-T046 — Implant energy and thermal exhaustion
**D** · E2 · A6 · S3 P0 F4 · L2 → **High** · `DESIGN`

For an implanted device, battery is a safety-relevant resource — depletion means an explant surgery,
and sustained RF or crypto load raises tissue temperature. An adversary that forces the radio to stay
awake, or that submits frames requiring expensive verification *on the implant*, converts a security
control into a physical harm vector. This inverts a normal assumption: on implants, doing more
cryptography can be the wrong answer.

*Mitigation:* strict duty-cycle limits, wake-up authentication that is cheap to reject (pre-shared
MAC before any signature check), energy budgeting per peer, and thermal monitoring with enforced
throttling.

#### <a id="ng-t047"></a>NG-T047 — RF interference and jamming
**D** · TB-2 · A6 · S3 P0 F4 · L3 → **High** · `DESIGN`

Out of scope to *prevent* in software; in scope to *detect and degrade safely*. Link loss must be
distinguishable from a quiet user, and must trigger the [NG-T044](#ng-t044) degraded mode rather than
leaving the last command latched — a latched throttle or joint velocity on link loss is the worst
possible failure.

### 4.6 Elevation of privilege

#### <a id="ng-t050"></a>NG-T050 — Policy engine has no enforcement point
**E** · TB-4 · A1 · S4 P4 F2 · L5 → **Critical** · `OPEN`

`PolicyEngine::check_capability`, `check_channel_access`, and `check_output_type` are never called
from `verify_neural_frame`, `verify_frame`, the examples, or any pipeline code — the crate has no
call site that connects a frame to a policy decision. Meanwhile
`verify_neural_frame` sets `report.application_authorized = true` unconditionally
(`src/attestation.rs:225`). Every capability is effectively held by everyone.

*Mitigation:* a single mandatory chokepoint — a `SecurityGateway` that takes (frame, app identity,
registry, policy, rate state) and returns either a policy-projected frame or a denial. No public API
should exist that returns frame data without passing through it; `verify_frame`'s current signature
invites exactly the wrong usage.

#### <a id="ng-t051"></a>NG-T051 — Raw-signal access via decoded side paths
**E/I** · TB-4 · A1 · S0 P4 F0 · L4 → **High** · `DESIGN`

Even with [NG-T030](#ng-t030) fixed, `DecodedOutput::Classification { class, confidence }` and
high-rate `CursorPosition` streams are a reconstruction channel: a confidence value sampled at
kilohertz is a lossy but usable view of the underlying feature signal. Capability boundaries drawn at
the *type* level leak through *rate* and *precision*.

*Mitigation:* policy must constrain rate and numeric precision per output type, not only which types
are permitted; treat "decoded output at full rate and precision" as a distinct, more privileged
capability than "decoded output".

#### <a id="ng-t052"></a>NG-T052 — Read-to-write escalation
**E** · TB-5 · A1, A3 · S4 P0 F3 · L3 → **Critical** · `DESIGN`

`Capability::ControlDevice` is a single flag covering "move a cursor" and "actuate a prosthetic
limb", and there is no separate capability for stimulation at all. Once the stimulation path exists
([NG-T016](#ng-t016)), a flat capability model means any app with device control reaches tissue.

*Mitigation:* split the capability lattice by consequence — `ControlPointer`, `ControlProsthetic`,
`ControlMobility`, `ControlVehicle`, `Stimulate{Sensory,Therapeutic}` — with stimulation requiring
separate, revocable, time-bounded grants and an independent hardware limiter that no software grant
can exceed.

#### <a id="ng-t053"></a>NG-T053 — Blacklist bypass on non-capability policy paths
**E** · E4 · A1 · S3 P3 F1 · L4 → **High** · `OPEN`

The blacklist is consulted in `check_capability` (`src/policy.rs:153`) but *not* in
`check_channel_access` (`src/policy.rs:175`) or `check_output_type` (`src/policy.rs:208`). A
blacklisted application still passes both, so any future call path that checks channels or outputs
without also checking a capability silently honours a revoked app. Revocation that is enforced on
only one of three paths is not revocation.

*Mitigation:* hoist the blacklist (and a general "is this app admissible" predicate) into a single
guard invoked at the start of every policy entry point; add a test that asserts every public
`check_*` denies a blacklisted app.

#### <a id="ng-t054"></a>NG-T054 — Development policy reaching production
**E** · E4 · A5, A1 · S3 P4 F1 · L3 → **High** · `OPEN`

`default_dev_policy` grants `ChannelAccessRule::AllChannels` at 60 fps (`src/policy.rs:239-257`) and
is a plain public constructor with nothing marking it as non-production. `min_trust_level` defaults
to the string `"provisional"` (`src/policy.rs:140`) and is never compared against
`TrustLevel::FullyTrusted` — it is a `String` where the type system already provides an enum.

*Mitigation:* gate dev policies behind a feature flag or a `#[cfg(debug_assertions)]`-style barrier;
make `min_trust_level` a `TrustLevel` and actually compare it; require an explicit
`Deployment::Production` construction that refuses provisional devices and dev policies.

#### <a id="ng-t055"></a>NG-T055 — Verdict is advisory; failures return `Ok`
**E** · E4 · A1 (via developer error) · S4 P3 F2 · L4 → **Critical** · `OPEN`

`verify_neural_frame` returns `Ok(report)` even when the device signature fails
(`src/attestation.rs:203-206`), relying on the caller to inspect `report.verdict`. The idiomatic Rust
reading of `verify_frame(&frame)?` is "verification succeeded", and the crate's own example
demonstrates the trap: it prints `"Attack DETECTED"` only in the `Err` arm. An API whose safe use
depends on the caller remembering to check a field inside a success value will be misused.

*Mitigation:* return `Result<TrustedFrame, RejectionReport>` where `TrustedFrame` is a type that
cannot be constructed except by successful verification, and make data accessors live on that type
only — misuse then fails to compile. Retain the detailed report inside the error for auditing.

#### <a id="ng-t056"></a>NG-T056 — `Verdict::Suspicious` is unreachable
**—** · E4 · — · S2 P0 F1 · L4 → **Low** · `OPEN`

The verdict lattice is binary in practice: the only assignments are `Trusted` and `Rejected`
(`src/attestation.rs:232-236`). A real deployment needs the middle state — degraded confidence that
permits cursor control but not prosthetic actuation, and that raises an alert. Without it, every
control has exactly one response (deny), which pushes operators toward disabling controls that
false-positive.

---

## 5. BCI-specific vector deep dives

Generic STRIDE finds "tampering with a data flow". It does not find "the signal is fabricated but
cryptographically authentic because the fabrication happened upstream of the signing boundary". These
four sections cover the vectors where the neural context changes the analysis.

### 5.1 Neural signal spoofing

**The core asymmetry:** authenticity ≠ veracity. Every cryptographic control NeuroGuard implements
answers "did this device produce this data?" None answers "did this data come from the user's
intent?" TB-1 is below the reach of cryptography, and it is precisely where the interesting attacks
live.

#### Attack tree

```
GOAL: cause the system to act on intent the user did not form
├── (a) Fabricate at the source (below TB-1)
│   ├── a1. Induced currents / EM injection into electrode leads   [A6]  → signed as genuine
│   ├── a2. Compromised analog frontend or ADC                     [A4]  → signed as genuine
│   └── a3. Firmware implant fabricating sample buffers            [A4]  → signed as genuine
├── (b) Replay genuine past activity
│   ├── b1. Whole-frame replay                     → NG-T018 (no freshness check) OPEN
│   ├── b2. Mid-stream chain insertion             → NG-T015 (fork accepted)      OPEN
│   └── b3. Selective replay of a specific command → both of the above
├── (c) Substitute the decoded intent, leaving samples untouched
│   └── c1. Rewrite decoded_output in transit      → NG-T010 (unsigned field)     OPEN
├── (d) Impersonate the device wholesale
│   └── d1. Self-signed frame with attacker key    → NG-T001                      OPEN
└── (e) Trigger a decoder backdoor
    └── e1. Present the trigger pattern via (a)    → NG-T013 (poisoning)          DESIGN
```

Branches (b), (c), and (d) are all cheap today. Branch (a) is expensive but *undefeatable by
cryptography* — it must be met by signal-domain plausibility checking.

#### Controls

1. **Freshness and ordering** (defeats b): monotonic per-device sequence number inside the signed
   payload, receiver-side acceptance window, tip-only chain extension.
2. **Full-frame authenticated encryption** (defeats c, d, and passive prep for a): AEAD over a
   canonical encoding with the decoder as an independent signing principal.
3. **Registry-bound identity** (defeats d): key resolved from `DeviceRegistry`, never from the frame.
4. **Signal plausibility gate** (only defence against a and e). Concretely, per-channel checks that
   an injected or fabricated signal struggles to satisfy simultaneously:
   - amplitude and slew within physiological range for the channel type
   - spectral shape consistent with the channel's baseline (1/f trend, band ratios), not a pure tone
     or saturated rail — note the shipped `SignalInjection` scenario emits `vec![999.9; 100]`, which
     no physiological check would pass, yet it verifies as `Trusted` today
   - inter-channel correlation structure consistent with the electrode geometry: a single-lead
     injection cannot easily reproduce the spatial covariance of real cortical activity
   - refractory/ISI statistics for spiking data
   - continuity with the immediately preceding window (no discontinuity in the state estimate)
   - liveness markers: presence of expected physiological artefacts (cardiac, respiratory, ocular)
     whose *absence* indicates synthesis
5. **Cross-modal corroboration** for high-consequence commands: require agreement between neural
   intent and an independent channel (residual EMG, eye tracking, a physical switch) before executing
   an irreversible action. This is the neural analogue of two-factor authentication and the strongest
   available answer to branch (a).
6. **Confidence-gated actuation**: decoder confidence and plausibility score become part of the
   frame, and `OutputType`-specific thresholds decide execute / degrade / deny. Feeds
   [NG-T056](#ng-t056)'s missing `Suspicious` state.

#### Residual risk

An adversary with full implant firmware control produces perfectly authentic, perfectly plausible
frames. That residual is irreducible in software; it is bounded by hardware root of trust, secure
boot, and manufacturing supply-chain integrity — controls that must be *named as assumptions*
([§11](#11-assumptions-and-residual-risk)) rather than left implicit.

### 5.2 Stimulation tampering

**The gap:** v0.0.1 has no write path. Everything above concerns brain→application. The
application→brain direction — where a bug or an attack deposits charge into tissue — is unmodelled,
so this section is design, not review.

#### Why it is not symmetric with the read path

| | Read path (neural → app) | Write path (app → neural) |
|---|---|---|
| Failure mode | Wrong action, wrong data disclosed | Direct physical injury: tissue damage, seizure, pain, mood/behaviour alteration |
| Reversibility | Command can be undone | Charge delivered cannot be withdrawn |
| Rate of harm | Bounded by actuator physics | Bounded only by hardware limits |
| Correct failure | Deny | *Ramp to zero* — abrupt cessation is itself harmful (rebound/withdrawal) |
| Verification timing | Can be post-hoc | Must be pre-delivery; there is no post-hoc |

#### Attack tree

```
GOAL: deliver harmful stimulation
├── (a) Out-of-range parameters
│   ├── amplitude / pulse width / frequency / duty cycle beyond clinical limits
│   └── charge-per-phase or charge density beyond tissue safety limits
├── (b) In-range parameters, harmful pattern
│   ├── kindling-like repetitive stimulation, each pulse individually legal
│   ├── resonant frequency selection to entrain pathological oscillation
│   └── targeting the wrong contact with otherwise-legal parameters
├── (c) Threshold / trigger manipulation in adaptive loops   → NG-T017
├── (d) Replay of a legitimate therapeutic burst at the wrong time or rate
├── (e) Denial of therapy (suppression) — for DBS, withdrawal is a safety event, not an outage
└── (f) Escalation from a read-only session to the stimulation path → NG-T052
```

#### Required design (v0.2.0)

1. **A `StimulationCommand` type** carrying contact/channel, waveform, amplitude, pulse width,
   frequency, burst duration, and charge balance — with parameters expressed in physical units, not
   raw device codes, so limits are checkable independent of the device.
2. **A three-layer limiter**, each independently sufficient to stop harm:
   - *Policy layer*: per-app, per-session capability with clinical envelope, revocable and
     time-bounded
   - *Middleware layer*: cumulative dose accounting over sliding windows (charge/phase, charge/sec,
     total energy per hour), pattern-level checks (kindling detection, minimum inter-burst interval),
     and a rate limiter that survives restart
   - *Hardware layer*: an interlock in the stimulator that clamps amplitude and charge regardless of
     any software command, configurable only through a physically or cryptographically distinct
     path. **The threat model must assume the software layers can be fully compromised**; this layer
     is what makes S4 outcomes survivable.
3. **Command authentication with freshness**, mandatory for every stimulation command — signed,
   sequence-numbered, short-lived (a stimulation command older than its deadline is void, never
   queued).
4. **Bidirectional provenance**: the existing chain extended to cover stimulation, so the record
   answers "what was delivered, on whose authority, under which policy version, in response to which
   biomarker".
5. **A defined safe state**: ramp-to-zero on link loss, verification failure, or watchdog expiry —
   with ramp profile per therapy, authored clinically, never a hard cut.
6. **User-controlled override**: a physical off/attenuate control on the person's body, outside the
   software path entirely. If the user cannot stop it without a computer, the design is wrong.

### 5.3 Feedback-loop DoS

**Why availability is a safety property here.** A closed-loop BCI is a control system with a human in
it. Classical DoS analysis asks "is the service up?"; control-theoretic analysis asks "is the loop
stable?" — and a loop can be *up* and *unstable*. Adding 80 ms of latency to a prosthetic control
loop tuned for 20 ms does not deny service; it produces oscillation while every component reports
healthy.

#### Attack tree

```
GOAL: destabilise or halt the loop
├── (a) Latency attacks
│   ├── a1. Uniform added delay        → phase margin loss → oscillation
│   ├── a2. Jitter injection           → unpredictable response, user over-corrects
│   └── a3. Selective delay of correction frames only → targeted instability
├── (b) Throughput attacks
│   ├── b1. Frame flooding                    → NG-T041 (rate limit unenforced)  OPEN
│   ├── b2. Verification-cost amplification   → NG-T043                          OPEN
│   └── b3. Memory exhaustion                 → NG-T042                          OPEN
├── (c) Chain-wedge attacks
│   └── c1. Drop one frame → all subsequent frames rejected → NG-T045            OPEN
├── (d) Failure-mode attacks
│   ├── d1. Force repeated verification failure → deny-by-default halts assistive function
│   └── d2. Link loss with last command latched → runaway                        NG-T044
└── (e) Human-loop attacks
    └── e1. Degrade quality just enough to force user compensation → fatigue,
            maladaptive motor learning that persists after the attack stops
```

Branch (e) has no IT analogue: the user *adapts* to a degraded interface, and that adaptation is
itself a lasting harm.

#### Controls

1. **An explicit latency budget** per `OutputType`, declared in policy — end-to-end deadline,
   maximum jitter, maximum consecutive drops. Without a declared budget there is no violation to
   detect.
2. **Deadline scheduling with staleness rejection**: every frame carries an issue time; the
   consumer discards frames past their deadline rather than acting on stale intent. Late data is
   worse than no data in a control loop.
3. **Constant-latency delivery** where feasible (emit at a fixed deadline regardless of early
   completion) — removes jitter as a channel and, incidentally, closes the decode-timing side channel
   in [NG-T033](#ng-t033).
4. **Loop-health monitoring as a security signal**: continuous measurement of round-trip latency,
   jitter, drop rate, and — the important one — *controller output variance*. A sudden rise in
   correction energy is the earliest observable of an induced-instability attack.
5. **Graceful degradation ladder** rather than binary allow/deny: full rate → reduced rate with
   increased smoothing → hold last safe state → controlled stop. Each rung must be a defined,
   clinically reviewed state ([NG-T044](#ng-t044)).
6. **Watchdog with a safe default**: absence of a valid frame within the deadline triggers the
   degraded mode automatically. Never latch the last command.
7. **Admission control ahead of crypto**: size cap, sequence window, and rate budget checked before
   signature verification, so flooding costs the attacker more than the defender
   ([NG-T043](#ng-t043)).
8. **Backpressure isolation**: one misbehaving application must not delay the safety-critical path —
   separate queues and priorities per `OutputType`, with prosthetic/mobility/vehicle strictly above
   cursor and recording.

### 5.4 Side-channel neural data leakage

**The framing that matters:** neural data is not rotatable and is re-identifiable. A leaked password
is replaced in seconds; a leaked neural signature is permanent, and it discloses attributes the user
never chose to express — health, affect, cognition. Side channels are therefore weighted higher in
this model than they would be in a conventional system.

#### Channel inventory

| Channel | Observable | Inference | Threat | Status |
|---|---|---|---|---|
| Frame size | `signal_data.len()` on the wire | Channel count, acquisition mode, whether a session is active | [NG-T031](#ng-t031) | DESIGN |
| Frame cadence | Inter-frame timing | Task engagement, attention, event onsets | [NG-T031](#ng-t031) | DESIGN |
| Traffic bursts | Volume envelope | Motor events, seizure activity, sleep/wake | [NG-T031](#ng-t031) | DESIGN |
| Decode latency | Response time | Cognitive load, signal quality, task difficulty | [NG-T033](#ng-t033) | OPEN |
| Error taxonomy | Which error variant, with what detail | Policy contents, whitelist membership, registry size, blacklist status | [NG-T032](#ng-t032) | OPEN |
| Commitment hashes | Published/anchored digests | Confirmation of candidate neural content (unkeyed hash) | [NG-T035](#ng-t035) | OPEN |
| Permitted decoded output | Cursor trajectory, confidence stream at full rate | Tremor, fatigue, intoxication, affect, re-identification | [NG-T034](#ng-t034), [NG-T051](#ng-t051) | DESIGN |
| Power/EM of the implant | Radiated emissions during processing | Activity state; classic hardware side channel | out of scope ([§1.2](#12-what-this-model-excludes)) | — |
| Log volume | Audit record rate | Session activity, alert conditions | [NG-T021](#ng-t021) | OPEN |

#### Controls

1. **Data minimisation at the boundary** — the projection control in [NG-T030](#ng-t030). Nothing
   else on this list matters as much: an app that never receives raw samples cannot leak them.
2. **Padding and constant-rate telemetry** for size/cadence channels, selectable per deployment
   because it costs implant energy ([NG-T046](#ng-t046)).
3. **Constant-latency delivery** for the timing channel (shared with [§5.3](#53-feedback-loop-dos)).
4. **Coarse external errors, detailed internal audit** for the error-oracle channel.
5. **Keyed commitments** (HMAC or per-frame salt) so provenance digests are hiding as well as
   binding.
6. **Rate and precision limits on decoded output** — quantise cursor coordinates and confidence to
   the task's actual requirement; a cursor needs pixels, not float32 at 1 kHz.
7. **Purpose limitation and retention limits** as enforced policy fields, with the honest
   acknowledgement that the residual — inference from legitimately permitted data — is bounded by
   governance, not by code ([NG-T034](#ng-t034)).

---

## 6. Risk register

41 threats: 9 Critical, 24 High, 6 Medium, 2 Low. By status: 21 OPEN, 5 PARTIAL, 15 DESIGN.
`OPEN` = present in v0.0.1 code; `PARTIAL` = control written but unreachable or incomplete;
`DESIGN` = subsystem does not exist yet.

| ID | Threat | STRIDE | S | P | F | L | Severity | Status |
|---|---|:-:|:-:|:-:|:-:|:-:|---|---|
| [T001](#ng-t001) | Implant impersonation via self-asserted key | S | 4 | 3 | 3 | 4 | **Critical** | OPEN |
| [T002](#ng-t002) | Neural signal spoofing below the signing boundary | S/T | 4 | 0 | 4 | 2 | High | DESIGN |
| [T003](#ng-t003) | Application identity spoofing | S | 3 | 4 | 2 | 5 | High | OPEN |
| [T004](#ng-t004) | Admin/clinician plane spoofing | S/E | 4 | 4 | 4 | 3 | **Critical** | DESIGN |
| [T005](#ng-t005) | Decoder/transform impersonation | S/T | 3 | 2 | 3 | 4 | High | PARTIAL |
| [T006](#ng-t006) | Signature transplantation via ambiguous serialisation | S/T | 3 | 1 | 2 | 2 | Medium | OPEN |
| [T010](#ng-t010) | Decoded output not covered by signature | T | 4 | 0 | 4 | 4 | **Critical** | OPEN |
| [T011](#ng-t011) | Signal tampering in transit | T | 4 | 0 | 4 | 3 | High | PARTIAL |
| [T012](#ng-t012) | Firmware downgrade / rollback | T/E | 4 | 2 | 3 | 3 | High | PARTIAL |
| [T013](#ng-t013) | Decoder model poisoning and swap | T | 4 | 2 | 4 | 2 | High | PARTIAL |
| [T014](#ng-t014) | Calibration and transformation tampering | T | 3 | 1 | 4 | 3 | High | PARTIAL |
| [T015](#ng-t015) | Provenance chain forking / replay insertion | T/R | 2 | 0 | 2 | 3 | Medium | OPEN |
| [T016](#ng-t016) | Stimulation parameter tampering | T/E | 4 | 0 | 4 | 3 | **Critical** | DESIGN |
| [T017](#ng-t017) | Closed-loop trigger threshold tampering | T | 4 | 1 | 3 | 2 | High | DESIGN |
| [T018](#ng-t018) | Timestamp manipulation / no freshness | T/S | 3 | 0 | 3 | 4 | High | OPEN |
| [T020](#ng-t020) | Intent is not attributable | R | 3 | 2 | 1 | 4 | High | DESIGN |
| [T021](#ng-t021) | Provenance volatile and unanchored | R/T | 1 | 0 | 1 | 4 | Medium | OPEN |
| [T022](#ng-t022) | Admin/policy changes unlogged | R | 3 | 3 | 2 | 4 | High | DESIGN |
| [T030](#ng-t030) | Raw neural exfiltration by over-permissioned app | I | 0 | 4 | 0 | 5 | High | OPEN |
| [T031](#ng-t031) | Traffic-analysis side channel | I | 0 | 3 | 0 | 3 | Medium | DESIGN |
| [T032](#ng-t032) | Errors leak policy/registry contents | I | 0 | 2 | 0 | 5 | Medium | OPEN |
| [T033](#ng-t033) | Timing side channels | I | 0 | 2 | 0 | 2 | Low | OPEN |
| [T034](#ng-t034) | Inference of protected attributes | I | 0 | 4 | 0 | 4 | High | DESIGN |
| [T035](#ng-t035) | Commitments as content-confirmation oracle | I | 0 | 3 | 0 | 2 | Medium | OPEN |
| [T036](#ng-t036) | Unintended speech disclosure | I | 1 | 4 | 1 | 3 | High | DESIGN |
| [T037](#ng-t037) | Plaintext telemetry | I | 1 | 4 | 0 | 4 | High | OPEN |
| [T040](#ng-t040) | Feedback-loop DoS | D | 4 | 0 | 4 | 3 | **Critical** | DESIGN |
| [T041](#ng-t041) | Frame flooding, no rate limiting | D | 3 | 0 | 4 | 5 | High | OPEN |
| [T042](#ng-t042) | Unbounded memory growth | D | 3 | 0 | 4 | 4 | High | OPEN |
| [T043](#ng-t043) | Verification-cost amplification | D | 3 | 0 | 3 | 4 | High | OPEN |
| [T044](#ng-t044) | Fail-secure / fail-safe conflict | D | 4 | 0 | 4 | 4 | **Critical** | DESIGN |
| [T045](#ng-t045) | Provenance-chain wedge | D | 3 | 0 | 4 | 4 | High | OPEN |
| [T046](#ng-t046) | Implant energy / thermal exhaustion | D | 3 | 0 | 4 | 2 | High | DESIGN |
| [T047](#ng-t047) | RF interference and jamming | D | 3 | 0 | 4 | 3 | High | DESIGN |
| [T050](#ng-t050) | Policy engine has no enforcement point | E | 4 | 4 | 2 | 5 | **Critical** | OPEN |
| [T051](#ng-t051) | Raw-signal access via decoded side paths | E/I | 0 | 4 | 0 | 4 | High | DESIGN |
| [T052](#ng-t052) | Read-to-write escalation | E | 4 | 0 | 3 | 3 | **Critical** | DESIGN |
| [T053](#ng-t053) | Blacklist bypass on non-capability paths | E | 3 | 3 | 1 | 4 | High | OPEN |
| [T054](#ng-t054) | Dev policy reaching production | E | 3 | 4 | 1 | 3 | High | OPEN |
| [T055](#ng-t055) | Verdict advisory; failures return `Ok` | E | 4 | 3 | 2 | 4 | **Critical** | OPEN |
| [T056](#ng-t056) | `Verdict::Suspicious` unreachable | — | 2 | 0 | 1 | 4 | Low | OPEN |

### 6.1 Control efficacy today

| Claimed control (README) | Reality in v0.0.1 | Threats it would cover once real |
|---|---|---|
| Device authentication | Signature verified against a key from the frame itself | T001, T002(d), T011 |
| Firmware integrity | `verify_firmware` written, never called; verdict hardcoded `true` | T012 |
| Decoder approval | `verify_model` written, never called | T005, T013 |
| Provenance chain | Present; excludes `decoded_output`, accepts forks, in-memory only | T010, T015, T021 |
| Policy compliance | Engine written, zero call sites | T003, T030, T050, T051, T052, T053 |
| Application authorisation | Hardcoded `true` | T003, T050 |
| Fail-secure defaults | No enforcement path to fail from | T044 |
| Encryption required | Field exists, never read | T037, T031 |
| Rate limiting | Struct exists, never read | T041, T043, T040 |

---

## 7. Detection signals

Prevention fails; a threat model that only lists preventive controls leaves the operator blind. Each
signal below should become a metric or event emitted by the middleware.

| Signal | Detects | Notes |
|---|---|---|
| Signature failures per device per minute | T001, T011 | A nonzero steady rate means an active adversary or a broken device — both need response |
| Sequence gaps / out-of-window timestamps | T015, T018, T045 | Distinguish loss from replay by whether the sequence *repeats* or merely skips |
| Duplicate commitments | T015 | Should be impossible once nonces are added; alert on any |
| Physiological plausibility score distribution | T002, T013 | Alert on distribution shift, not just individual outliers — poisoning shows as drift |
| Inter-channel correlation collapse | T002 | Single-lead injection breaks spatial covariance |
| Absence of expected artefacts (cardiac/respiratory/ocular) | T002 | Synthesis usually forgets the noise |
| Decoder confidence distribution shift | T013, T014 | Calibration drift and poisoning both show here first |
| Command entropy / repetitiveness | T013(e1), T016(b) | Kindling patterns and backdoor triggers are unusually stereotyped |
| Round-trip latency, jitter, drop rate | T040, T047 | Per `OutputType`; alert against the declared budget |
| Controller output variance / correction energy | T040 | Earliest observable of induced instability |
| Cumulative stimulation dose vs envelope | T016, T017 | Must be tracked in the middleware, not only the device |
| Policy denial rate per app | T003, T030, T050, T053 | A well-behaved app denies rarely; probing looks like enumeration |
| Error-variant frequency per app | T032 | Enumeration of the policy oracle |
| Raw-signal request rate | T030, T034 | Purpose-limitation violations look like volume anomalies |
| Frame size/rate entropy on the link | T031 | Also verifies that padding is actually working |
| Admin mutation events | T004, T022 | Every one is security-relevant; none should be silent |
| Implant duty cycle, temperature, battery slope | T046 | Physical safety telemetry doubling as attack detection |

---

## 8. Validation: tests, simulation, and fuzzing

The virtual BCI is the right place to make this model executable — a threat that cannot be simulated
cannot be regression-tested.

### 8.1 Existing `AttackType` coverage

| `AttackType` | Threats | Detected today |
|---|---|---|
| `ReplayAttack` | T018, T015 | ✗ — verdict `Trusted` |
| `SignalInjection` | T002, T011 | ✗ — no plausibility check |
| `MaliciousDecoder` | T005, T013 | ✗ — `verify_model` uncalled |
| `FirmwareDowngrade` | T012 | ✗ — `verify_firmware` uncalled |
| `DeviceImpersonation` | T001 | ✗ — key taken from frame |
| `TamperedCalibration` | T014 | ✗ — `transformation_hash` unverified |
| `CommandModification` | T010 | ✗ — field unsigned |
| `DataExfiltration` | T030, T034 | ✗ — no policy enforcement |

`tests/threat_model.rs` asserts that every `AttackType` variant maps to at least one catalogued
threat, so adding a scenario without modelling it fails the build.

### 8.2 Scenarios to add

| Proposed variant | Threats | What it must produce |
|---|---|---|
| `ChainFork` | T015 | Frame branching from a non-tip commitment |
| `CommitmentCollision` | T015 | Two frames, same second, identical samples |
| `SignatureTransplant` | T006 | Two frames whose `signable_data()` collide |
| `CrossModelConfusion` | T006, T012 | Valid signature with `model` swapped to another family |
| `RateFlood` | T041, T043 | Frames far above `max_fps` |
| `OversizedFrame` | T042 | `signal_data` beyond `max_signal_size` |
| `LatencyInjection` | T040 | Frames delayed/jittered past the loop deadline |
| `SelectiveDrop` | T040, T045 | Drop exactly one frame, observe wedge |
| `LinkLoss` | T044, T047 | Silence; assert the safe state, not a latch |
| `StimulationOverdose` | T016 | Out-of-envelope charge (needs the write path) |
| `KindlingPattern` | T016 | In-envelope pulses at a harmful cadence |
| `ThresholdShift` | T017 | Adaptive trigger threshold moved slightly |
| `TrafficAnalysis` | T031 | Observer-side scenario asserting padding hides activity |
| `PolicyProbe` | T032 | Enumeration via error variants |
| `BlacklistedAppFlow` | T053 | Revoked app exercising channel/output paths |

### 8.3 Fuzzing targets

Ranked by expected yield, given that the crate is `#![forbid(unsafe_code)]` (memory-safety bugs are
not the concern; logic and resource bugs are):

1. **`NeuralFrame` deserialisation** — arbitrary bytes into `serde_json`/`bincode`. Targets T042
   (allocation before size check) and panics on malformed input.
2. **`signable_data` / `compute_commitment` differential fuzzing** — search for distinct frames with
   identical outputs. Directly targets T006 and the T015 collision; a collision found here is a
   proof, not a hypothesis.
3. **`ProvenanceChain` operation sequences** — random add/verify/fork/duplicate orderings, asserting
   the invariant "`verify_chain().is_ok()` ⟺ no fork, no duplicate, no gap".
4. **`PolicyEngine` decision consistency** — random policies and requests, asserting a blacklisted
   app is denied on *every* entry point (T053) and that no capability is grantable that was not
   registered.
5. **`f32` sample handling** — NaN, ±inf, subnormals, ±0.0 through hashing and plausibility checks.
   `-0.0` and `+0.0` hash differently while comparing equal; NaN payload bits are attacker-chosen
   space inside a "valid" frame and a candidate covert channel.
6. **Signal plausibility gate** (once built) — adversarial search for synthetic signals that pass.
   This is the fuzzing target with the most research value.

---

## 9. Remediation roadmap

Ordered by risk reduction per unit of work, not by module.

### 9.1 v0.1.0 — protocol hardening (breaking)

These change the wire format and should land together, before any hardware integration.

1. **Sign the whole frame, canonically.** Include `decoded_output`, `manufacturer`, `model`, a
   sequence number, and a nonce; length-prefix every field; add a domain-separation tag. Closes
   T010, T006; enables T015, T018.
2. **Resolve keys from the registry.** `verify_neural_frame` takes `&DeviceRegistry`; remove
   `public_key` from the wire format. Closes T001.
3. **Wire the written-but-unreachable checks** — `verify_firmware`, `verify_model`, trust level —
   into the pipeline, and delete the hardcoded `true` assignments. Closes T012 (with SVN), T005.
4. **Make verification type-safe.** `Result<TrustedFrame, RejectionReport>`; frame data accessible
   only through `TrustedFrame`. Closes T055.
5. **Freshness.** Monotonic sequence per device + receiver acceptance window + tip-only chain
   extension + duplicate-commitment rejection. Closes T018, T015.
6. **Admission control before crypto.** Size cap enforcing `max_signal_size`, rate budget enforcing
   `RateLimit`, cheap checks first. Closes T041, T042, T043.
7. **A single enforcement chokepoint** (`SecurityGateway`) that no data path bypasses, with the
   blacklist hoisted into a shared guard. Closes T050, T053.

### 9.2 v0.1.x — privacy and transport

8. **Per-policy frame projection** — strip raw samples unless `ReadRawSignal` is held, with attested
   projection recorded in the provenance chain. Closes T030, mitigates T034, T051.
9. **AEAD transport with forward secrecy**, keys bound to attested identity; enforce
   `require_encryption`. Closes T037.
10. **Two-tier errors** — coarse externally, detailed in audit. Closes T032.
11. **Keyed/salted commitments.** Closes T035.
12. **Persistent, append-only, externally anchored provenance** with bounded memory and explicit
    `Gap` links. Closes T021, T045; enables T020.
13. **Rate and precision limits per output type.** Mitigates T051.

### 9.3 v0.2.0 — safety-critical paths

14. **Stimulation write path** with the three-layer limiter of [§5.2](#52-stimulation-tampering).
    Closes T016, T052; enables T017.
15. **Latency budgets, deadline scheduling, staleness rejection, watchdog.** Closes T040.
16. **Per-`OutputType` degraded-mode ladder**, clinically authored. Closes T044, T047.
17. **Capability lattice split by consequence.** Closes T052; mitigates T003.
18. **Signal plausibility gate** with the checks in [§5.1](#51-neural-signal-spoofing), feeding a
    reachable `Verdict::Suspicious`. Mitigates T002, T013; closes T056.
19. **Authenticated admin plane** — signed approvals, two-person rule for stimulation limits, full
    audit. Closes T004, T022.
20. **Production deployment mode** — refuses dev policies and provisional trust levels; typed
    `min_trust_level`. Closes T054.

### 9.4 v0.3.0 and beyond — research

21. Purpose limitation as an enforced policy dimension, with retention (T034).
22. Cross-modal corroboration for irreversible actions (T002).
23. Constant-rate/padded telemetry with an energy-cost model (T031 vs T046).
24. Utterance gating for speech neuroprostheses (T036).
25. Training-pipeline provenance and behavioural acceptance testing for decoders (T013).
26. TEE/enclave-measured decoder execution (T005).

---

## 10. Standards alignment

This model is intended to feed, not replace, the artefacts a regulated programme needs.

| Framework | Relationship |
|---|---|
| **ISO 14971** (risk management for medical devices) | The S dimension of [§1.4](#14-risk-rubric) is the bridge; each S≥3 threat should become a hazard in the risk file with a documented risk-control measure |
| **IEC 62304** (medical device software lifecycle) | Threat IDs are traceable to requirements; the [§9](#9-remediation-roadmap) roadmap is the change plan |
| **IEC 81001-5-1** (health software security lifecycle) | This document is the threat-modelling activity output |
| **ANSI/AAMI SW96** (medical device security risk management) | Security risk register = [§6](#6-risk-register) |
| **FDA premarket cybersecurity guidance (2023)** | Requires a threat model, SBOM, and a vulnerability-management plan; this covers the first, and [§8](#8-validation-tests-simulation-and-fuzzing) supports the third |
| **NIST SP 800-30** | Likelihood/impact framing, adapted for safety |
| **CVSS v4** | Deliberately *not* used as the primary score — its Availability metric cannot express "denial of service equals physical injury". Retained for supply-chain dependency findings only |
| **MITRE ATT&CK / ICS** | Closest analogue for the actuator path; the stimulation limiter mirrors ICS safety-instrumented-system practice |

---

## 11. Assumptions and residual risk

Stated so they can be challenged rather than assumed away.

**Assumptions (each is a dependency, not a fact):**

- A1. The implant possesses or can be given a hardware root of trust with a private key that never
  leaves the device. Without this, T001 cannot be fully closed.
- A2. Secure boot and signed firmware exist below NeuroGuard. NeuroGuard verifies *hashes*; it
  cannot verify what is actually executing on the implant.
- A3. The host OS provides a trustworthy application identity (peer credentials or code signing).
  Without this, T003 has no technical mitigation.
- A4. Clinical envelopes for stimulation parameters are authoritative, reviewed, and available to the
  middleware in physical units.
- A5. A time source good enough for freshness windows exists on the host; the implant clock is
  assumed unreliable.
- A6. Decoder training data and pipeline are outside NeuroGuard's control in v0.x; poisoning is
  addressed only at runtime.

**Residual risk after the full roadmap:**

| Residual | Why it remains | Bounded by |
|---|---|---|
| Full implant firmware compromise | Signing occurs below all software controls | Hardware root of trust, secure boot, supply chain |
| Decoder poisoning that survives acceptance testing | Behavioural testing is sampling | Runtime plausibility, confidence-gated actuation, cross-modal corroboration |
| Inference from legitimately permitted data | No technical control expresses purpose | Governance, retention limits, contract, regulation |
| Physical/surgical attack | Out of scope | Clinical controls |
| RF jamming | Cannot be prevented in software | Safe-state design, detection |
| Compromised host with kernel privileges | Middleware runs there | TEE, remote attestation of the host |
| A user coerced into forming genuine intent | The signal is authentic and plausible | Nothing technical. Named for honesty |

---

## 12. Maintaining this document

- Every new `AttackType` variant needs a catalogue entry; `tests/threat_model.rs` enforces this.
- Every threat ID in `threat-catalog.json` must appear in this document and vice versa; the same
  test enforces this.
- When a threat's status changes, update `threat-catalog.json` **and** the corresponding
  characterisation test in `tests/threat_model.rs` — those tests assert *current* (vulnerable)
  behaviour and are designed to fail loudly when a fix lands, which is the signal to update both.
- Re-run the model on: any protocol change, any new `OutputType` or `Capability`, any new trust
  boundary (hardware integration, cloud sync, multi-device), and any incident.
