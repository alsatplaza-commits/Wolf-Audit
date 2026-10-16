# Security policy

**Pre-release development software. Not yet suitable as a trusted security gate.**

- Use only on codebases you own or are explicitly authorized to audit.
- Report security vulnerabilities **privately**, not in public Issues. Maintainers should enable GitHub **Private vulnerability reporting** under repository security settings once the public repository is created.
- Until that is enabled, do not publish exploit details publicly. Request a private disclosure contact from the repository owner without posting details.
- Do not put secret values or customer code in bug reports, PRs, CI logs, or artifacts.
- Never run untrusted code submitted through pull requests with elevated token permissions or secrets. No `pull_request_target` workflows that check out untrusted head revisions.
- Scanner result `NO_HEURISTIC_FINDINGS` means only that the limited current rules detected nothing; **not certified secure**.

- `--osv-online` is an explicit opt-in external request. It discloses package names, versions and ecosystems to OSV; obtain permission before scanning confidential dependency inventories.
- Keep private audit evidence, file hashes, SBOMs, vulnerability matches and gate reports off public branches and public CI artifacts.
- Automated policy gate `PASS` never constitutes an independent FFI review or security certification.
- A scan bound to one authorized customer is a local scope limit, not a security certification. Scans refuse symlink roots, symlink targets, reparse points, and hard links that also exist outside the scan root. They refuse commit claims that are not the clean local HEAD. Ignored files, assume-unchanged or skip-worktree entries, and sparse checkout also reject the claim.
- Evidence outputs from a bound scan must stay inside that customer directory. Symlink and junction output, policy, and baseline paths are not followed. Duplicate customer ids in an authorization file are rejected.
- Evidence SHA-256 detects accidental alteration but does not attest provenance without a separately trusted signature.
- Do not commit signed object URLs or query credentials. A workflow history entry on `wolf-music-downloads` already contains one; its value is intentionally not copied here. New scans flag that URL shape and omit the matched text.
