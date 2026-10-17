# WOLF AUDITOR architecture

## Trust boundaries

1. Auditor code and build infrastructure are owned by the WOLF AUDITOR project.
2. Audit targets are treated as **untrusted input**, never as trusted executable steps.
3. Target repository secrets, private source, raw logs, and vulnerable proofs-of-concept must not be copied to a public repository or posted as public CI artifacts.
4. Sandboxed dynamic tooling, a worker authorization model, and an explicit human approval gate are prerequisites for any future DAST/fuzzing/runtime modules.
5. Scanner errors, missing targets, truncated coverage, and unsupported analysis domains must never turn into PASS.
6. Evidence and human sign-off are different. Auditor output is not its own independent certification.

## Delivery phases

- P0 (implemented prototype): Offline read-only scanning, provenance hash, incomplete status, heuristic rules, CLI and unit tests.
- P1 (partial, prototype): Python AST heuristics, offline Cargo/npm/pip component inventory, SARIF 2.1.0 and CycloneDX 1.6 output. External adapters, independent verification, CVE feeds, production release policy and full language coverage are NOT implemented.
- P2 (partial prototype): Rust token heuristic for `unsafe`, FFI attributes, raw pointers and `static mut`; read-only Windows API name inventory; a caller-supplied fuzz harness with seed, iteration, timeout and allocation limits. This is not a Rust parser, not live process inspection, and not fuzz coverage of the audited tree. Unclosed Rust literals and native files that were not runtime-checked stay INCOMPLETE. DAST, native Windows fuzzing, and memory-exploit proof remain unsupported.
- P3 (planned): Sandboxed runtime verification, AI-agent security, enterprise roles, multi-project policies and signed human review.

## Product rules

**PRESERVE WORKING SYSTEMS. NO REFACTOR WITHOUT DEFECT. MINIMUM SAFE CHANGE.** Never mark a blocked security review as independently approved based solely on self-generated tests.

- P1.5 (implemented prototype): Optional bounded OSV querybatch, fail-closed advisory handling, strict JSON release policies, Kubernetes/Terraform heuristics, .env/token/PEM indicators, deterministic report comparison, OSV/CycloneDX vulnerability references. All require explicit interpretation; neither OSV nor policy output independently certifies a product.
- Network boundary: no package metadata leaves the machine unless `--osv-online` is provided; private scans must not use public CI artifacts.
- Deliberately unsupported: DAST, native Windows fuzzing, memory exploit proof, broad taint/dataflow, signed reviewer attestation, full CVE completeness.
