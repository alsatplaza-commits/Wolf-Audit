# WOLF AUDITOR 🐺

**Independent repository. Modular software security audit platform, early development.**

> This repository begins with a *working but limited* read-only audit prototype. It is NOT a mature SAST/DAST platform, a penetration-testing service, an FFI safety certification, or a substitute for a qualified independent security review.

## Available now (with Linux / Windows regression tests)

- Bounded, offline, read-only source tree traversal (no execution of the project being scanned).
- Inventory Rust `unsafe` blocks, `unsafe` attributes, `extern "C"` / `extern "system"` boundaries, `no_mangle` / `export_name` / `link_name`, raw pointers, `static mut`, and selected FFI calls for expert review. Comments and string literals are not treated as code. This is a token heuristic, **not** a Rust parser. `unsafe` is **not** proof of a vulnerability.
- Inventory selected Windows process, privilege, and dynamic-load API names in C/C++ source. The scanner does not open processes. On every host the Windows runtime check stays `NOT_EXECUTED` and native source files are INCOMPLETE until a real runtime inspection exists.
- Controlled fuzz harness for a callable the caller supplies: deterministic seeds, iteration and timeout limits, crash/timeout/allocation separation, and replay bytes. Repository scanning does not execute it and does not claim fuzz coverage.
- Flag non-SHA-pinned `uses:` dependencies in GitHub Actions workflow files (heuristic).
- Flag some hard-coded tokens/keys, with the matched line/value omitted from reports (heuristic).
- JSON evidence: source file SHA-256 manifest, finding provenance, coverage gaps, deterministic report hash.
- Honest results: `NO_HEURISTIC_FINDINGS`, `REVIEW_REQUIRED`, `INCOMPLETE`. These are NOT independent PASS certification.
- Python AST rule-based SAST for dynamic execution, selected unsafe serialization patterns and shell-enabled subprocesses.
- GitHub workflow triage for risky event-to-shell interpolation, write-all permissions and privileged PR triggers.
- Dockerfile triage for mutable latest tags and root user.
- Offline dependency component inventory for Cargo.lock, npm package-lock.json and simple pip requirements.txt files.
- Deterministic CycloneDX 1.6 inventory (no vulnerability database lookup) and SARIF 2.1.0 triage output.
- **OSV advisory matching (opt-in):** Bounded HTTPS queries of exact package versions; failed or partial checks remain INCOMPLETE.
- **Release policy engine:** Strict JSON schemas, fail-closed incomplete coverage and automatic blocking of matching advisories unless explicitly changed by policy.
- **IaC heuristics:** Terraform public ACL / network exposure and Kubernetes privileged container signals.
- **Secret indicators:** PEM private-key headers, GitHub-token-like strings and environment-file inspection without emitting matched values.
- **Evidence comparison:** Verify SHA-256 report digests, produce redacted new/resolved findings across scans.
- **Advisory reporting:** Add matched OSV references to SARIF and CycloneDX vulnerability entries.
- Linux/Windows unit-test CI without privileged tokens.

## Run

Requires Python 3.11+ and no external dependencies:

```bash
python -m unittest discover -s tests -v
python -m wolf_auditor . --output local-report.json
python -m wolf_auditor /path/to/authorized-project --output result.json --sarif result.sarif --sbom result.cdx.json
# Explicitly disclose package names/versions to OSV only after authorization:
python -m wolf_auditor /path/to/authorized-project --osv-online --output osv-report.json --sbom osv-sbom.json
# Automated release policy (this is NOT independent expert sign-off):
python -m wolf_auditor /path/to/authorized-project --policy policies/high-risk.json --gate-output gate.json --output report.json
# Recheck against an earlier report:
python -m wolf_auditor /path/to/authorized-project --baseline previous-report.json --delta-output delta.json --output current-report.json
```

Exit codes without policy: `0` no findings; `1` review findings; `2` incomplete/error.
With policy: `0` policy PASS, `3` policy BLOCK, `2` incomplete/error.
A policy PASS is **not** a security certification. Inspect `coverage_gaps` and `excluded_paths` on every report. Outputs are local and MUST NOT be committed for sensitive targets.

## Remaining platform architecture (planned, not implemented)

Target domains (several limited baseline components are implemented, NOT complete products): SAST, DAST, SCA, binary analysis, memory/FFI, fuzzing, API security, secrets, SBOM/supply chain, cloud/IaC, runtime audit, AI agent security, threat modeling, adversarial lab, evidence, release governance. Future audit drivers MUST be isolated, permission-scoped, and cannot claim unsupported checks as PASS.

### Coverage and limitation notes

- Python scanning uses AST heuristics, not interprocedural taint analysis. Alias calls and control flow are not fully understood.
- The OSV advisory service is queried **only** using `--osv-online` and transmits package names, exact versions and ecosystems. No vulnerability checking runs automatically.
- Npm v1/v2/v3 and Cargo component parsing are inventories, not complete dependency graph attestations.
- Unsupported lockfile input and nontrivial requirement directives must be counted as INCOMPLETE coverage, never silently promoted to PASS.
- SARIF findings are redacted rule/location leads, not proof-of-exploit.
- IaC checks are limited pattern searches, not complete Terraform HCL/Kubernetes YAML parsers.
- Local hashes detect unintentional report modification, not independent authenticity or human approval.
- No dynamic execution, endpoint probes or private repository scans occur automatically.
- No FFI expert-review register is self-approved by an automated WOLF AUDITOR result.
- Rust FFI inventory misses macros and some literal forms. A gap is recorded when a comment, string, or attribute is unclosed. It is not compiler-accurate.
- Windows native runtime inspection is not implemented. Finding an API name is not proof that the call is reachable or permitted.
- The fuzz harness never runs code from the audited tree. `coverage_claim` stays false.

The WOLF SENTINEL private repository is **not bundled**, imported, mirrored, or exposed here. It can be an authorized private test target later through a safe workflow with separate access controls.

## Licensing

**No open-source license has been selected yet.** Public visibility does not automatically grant permission to reproduce, adapt, or redistribute source code beyond applicable law and GitHub's Terms. The owner will make a deliberate licensing decision before outside reuse or contributions are accepted.

## Security

See [SECURITY.md](SECURITY.md). Do not commit credentials, private target repositories, sensitive audit reports, exploited samples, or customer data.
