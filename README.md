# WOLF AUDITOR 🐺

**Independent repository. Modular software security audit platform, early development.**

> This repository begins with a *working but limited* read-only audit prototype. It is NOT a mature SAST/DAST platform, a penetration-testing service, an FFI safety certification, or a substitute for a qualified independent security review.

## Available now (subject to CI verification)

- Bounded, offline, read-only source tree traversal (no execution of the project being scanned).
- Inventory Rust `unsafe` blocks for expert review. `unsafe` is **not** treated as proof of a vulnerability.
- Flag non-SHA-pinned `uses:` dependencies in GitHub Actions workflow files (heuristic).
- Flag some hard-coded tokens/keys, with the matched line/value omitted from reports (heuristic).
- JSON evidence: source file SHA-256 manifest, finding provenance, coverage gaps, deterministic report hash.
- Honest results: `NO_HEURISTIC_FINDINGS`, `REVIEW_REQUIRED`, `INCOMPLETE`. These are NOT independent PASS certification.
- Python AST rule-based SAST for dynamic execution, selected unsafe serialization patterns and shell-enabled subprocesses.
- GitHub workflow triage for risky event-to-shell interpolation, write-all permissions and privileged PR triggers.
- Dockerfile triage for mutable latest tags and root user.
- Offline dependency component inventory for Cargo.lock, npm package-lock.json and simple pip requirements.txt files.
- Deterministic CycloneDX 1.6 inventory (no vulnerability database lookup) and SARIF 2.1.0 triage output.
- Linux/Windows unit-test CI without privileged tokens.

## Run

Requires Python 3.11+ and no external dependencies:

```bash
python -m unittest discover -s tests -v
python -m wolf_auditor . --output local-report.json
python -m wolf_auditor /path/to/authorized-project --output result.json --sarif result.sarif --sbom result.cdx.json
```

Exit codes: `0` for no findings; `1` for review findings; `2` for incomplete/error. Inspect `coverage_gaps` on every report. Outputs are local and MUST NOT be committed for sensitive targets.

## Remaining platform architecture (planned, not implemented)

Target domains (several limited baseline components are implemented, NOT complete products): SAST, DAST, SCA, binary analysis, memory/FFI, fuzzing, API security, secrets, SBOM/supply chain, cloud/IaC, runtime audit, AI agent security, threat modeling, adversarial lab, evidence, release governance. Future audit drivers MUST be isolated, permission-scoped, and cannot claim unsupported checks as PASS.

### Coverage and limitation notes

- Python scanning uses AST heuristics, not interprocedural taint analysis. Alias calls and control flow are not fully understood.
- The manifest scanner does **not** query OSV/NVD/CVE data and cannot label a version vulnerable or safe.
- Npm v1/v2/v3 and Cargo component parsing are inventories, not complete dependency graph attestations.
- Unsupported lockfile input and nontrivial requirement directives must be counted as INCOMPLETE coverage, never silently promoted to PASS.
- SARIF findings are redacted rule/location leads, not proof-of-exploit.
- No dynamic execution, external network tests, endpoint probes or private repo scanning occurs automatically.

The WOLF SENTINEL private repository is **not bundled**, imported, mirrored, or exposed here. It can be an authorized private test target later through a safe workflow with separate access controls.

## Licensing

**No open-source license has been selected yet.** Public visibility does not automatically grant permission to reproduce, adapt, or redistribute source code beyond applicable law and GitHub's Terms. The owner will make a deliberate licensing decision before outside reuse or contributions are accepted.

## Security

See [SECURITY.md](SECURITY.md). Do not commit credentials, private target repositories, sensitive audit reports, exploited samples, or customer data.
