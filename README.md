# WOLF AUDITOR 🐺

**Independent repository. Modular software security audit platform, early development.**

> This repository begins with a *working but limited* read-only audit prototype. It is NOT a mature SAST/DAST platform, a penetration-testing service, an FFI safety certification, or a substitute for a qualified independent security review.

## Available now (verified by local unit tests)

- Bounded, offline, read-only source tree traversal (no execution of the project being scanned).
- Inventory Rust `unsafe` blocks for expert review. `unsafe` is **not** treated as proof of a vulnerability.
- Flag non-SHA-pinned `uses:` dependencies in GitHub Actions workflow files (heuristic).
- Flag some hard-coded tokens/keys, with the matched line/value omitted from reports (heuristic).
- JSON evidence: source file SHA-256 manifest, finding provenance, coverage gaps, deterministic report hash.
- Honest results: `NO_HEURISTIC_FINDINGS`, `REVIEW_REQUIRED`, `INCOMPLETE`. These are NOT independent PASS certification.
- Linux/Windows unit-test CI without privileged tokens.

## Run

Requires Python 3.11+ and no external dependencies:

```bash
python -m unittest discover -s tests -v
python -m wolf_auditor . --output local-report.json
python -m wolf_auditor /path/to/authorized-project --output result.json
```

Exit codes: `0` for no findings; `1` for review findings; `2` for incomplete/error. Inspect `coverage_gaps` on every report. Outputs are local and MUST NOT be committed for sensitive targets.

## Target platform architecture (planned, not implemented)

16 plug-in domains: SAST, DAST, SCA, binary analysis, memory/FFI, fuzzing, API security, secrets, SBOM/supply chain, cloud/IaC, runtime audit, AI agent security, threat modeling, adversarial lab, evidence, release governance. Future audit drivers MUST be isolated, permission-scoped, and cannot claim unsupported checks as PASS.

The WOLF SENTINEL private repository is **not bundled**, imported, mirrored, or exposed here. It can be an authorized private test target later through a safe workflow with separate access controls.

## Licensing

**No open-source license has been selected yet.** Public visibility does not automatically grant permission to reproduce, adapt, or redistribute source code beyond applicable law and GitHub's Terms. The owner will make a deliberate licensing decision before outside reuse or contributions are accepted.

## Security

See [SECURITY.md](SECURITY.md). Do not commit credentials, private target repositories, sensitive audit reports, exploited samples, or customer data.
