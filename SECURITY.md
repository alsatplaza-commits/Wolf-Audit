# Security policy

**Pre-release development software. Not yet suitable as a trusted security gate.**

- Use only on codebases you own or are explicitly authorized to audit.
- Report security vulnerabilities **privately**, not in public Issues. Maintainers should enable GitHub **Private vulnerability reporting** under repository security settings once the public repository is created.
- Until that is enabled, do not publish exploit details publicly. Request a private disclosure contact from the repository owner without posting details.
- Do not put secret values or customer code in bug reports, PRs, CI logs, or artifacts.
- Never run untrusted code submitted through pull requests with elevated token permissions or secrets. No `pull_request_target` workflows that check out untrusted head revisions.
- Scanner result `NO_HEURISTIC_FINDINGS` means only that the limited current rules detected nothing; **not certified secure**.
