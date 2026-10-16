# Wolf-Audit P1 technical audit

Independent engineering record. This is not a security certification, a penetration test, or a claim that every vulnerability class is detected. The words PASS, REVIEWED, and VERIFIED are not used as conclusions.

P1 gate decision: **COMPLETE**.

## Repository identity

| Item | Value |
| --- | --- |
| Repository | alsatplaza-commits/Wolf-Audit |
| Branch | `cursor/p1-completion-gate-31ed` |
| Base SHA | `d5ffd6111ae5b495bc713b57b40ceba0266c2b08` (`origin/main`) |
| Code SHA exercised by the green Actions run below | `71b60811515dc069f77478f26dc49914defbc09a` |
| Draft pull request | https://github.com/alsatplaza-commits/Wolf-Audit/pull/7 |
| PR #4 head, not modified | `e4d74128b0f93c86cc2fafa2d0781690957fb7b7` |
| PR #5 head, not modified | `63716997589cb7caafcb0389f9bbd0584639a18a` |
| PR #6 head, not modified | `fb551c72472f7950a101e3be4f37f9a2ee7ed749` |

The commit that adds this file is the child of `71b60811515dc069f77478f26dc49914defbc09a`. It does not change the scanner. A reviewer must match the pull request head to the blob they are reading. Actions URLs for that documentation commit belong in the pull request description after those jobs finish.

## Scope

Included: files tracked on `origin/main` at the base SHA, plus the commits on this branch. P1.5 modules (`osv.py`, `policy.py`, `iac.py`, `delta.py`) were not behavior-changed. Their existing tests still run.

Not included: Enterprise code, a root `LICENSE`, P2 fuzzing or FFI, a full CVE feed, and language parsers other than the existing heuristics.

`git rev-list --count origin/main` at the base is 4.

## Tools and versions

| Tool | Version and evidence |
| --- | --- |
| Python, local suite | 3.12.3, `python3 --version` |
| Git, local | 2.43.0, `git --version` |
| jsonschema | 4.23.0, `importlib.metadata.version("jsonschema")` inside `tests/test_p1_completion.py` |
| SARIF schema | OASIS errata 01, SHA-256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`, 112768 bytes. Source URL: `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json` |
| CycloneDX schema | specification tag 1.6.1, SHA-256 `efc54d749e32a6e16abd19394b80b4c67d846e12c782e04505130375f94ea541`, 262597 bytes. Source URL: `https://raw.githubusercontent.com/CycloneDX/specification/1.6.1/schema/bom-1.6.schema.json` |
| CI Python | The workflow step is named `Python 3.11+` and finished on both runners. The exact interpreter string was not copied out of the log download. |

jsonschema is installed only in the test job (`python -m pip install jsonschema==4.23.0`). It is not a `pyproject.toml` dependency. The scanner remains stdlib-only.

The CycloneDX schema file contains its own Apache-2.0 comment for that schema. That comment is not a license grant for Wolf-Audit. No root `LICENSE` was added.

## Commands

Schema fetch, from the audit machine, before the fixtures were committed:

```text
curl -fsSL -o sarif-schema-2.1.0.json \
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
curl -fsSL -o bom-1.6.schema.json \
  https://raw.githubusercontent.com/CycloneDX/specification/1.6.1/schema/bom-1.6.schema.json
```

Local suite, with jsonschema on `PYTHONPATH` so the schema tests can import it:

```text
PYTHONPATH=/tmp/p1-pkgs python3 -m unittest discover -s tests -q
```

Result on this worktree before the documentation commit: 66 tests, exit code 0. The previous main tree had 57 tests. The nine additions are in `tests/test_p1_completion.py`. Older test modules were not deleted or replaced.

Self-audit of this worktree:

```text
python3 -m wolf_auditor .
```

Result: engine status `REVIEW_REQUIRED`, 16 files scanned, 1 finding, 0 coverage gaps, process exit 1. The finding is `PRIVATE_KEY_MATERIAL` at `tests/test_security_v03.py` line 242. The matched text is not copied into the report. Exit 1 does not fail CI. Exit 2 would.

## File changes on this branch

| Path | Change |
| --- | --- |
| `wolf_auditor/analysis.py` | Module-level import aliases, safe YAML loader exception, `marshal.load`, `builtins.eval` / `builtins.exec` |
| `wolf_auditor/engine.py` | When the file budget stops the walk, add gap `scan_stopped_before_remaining_files` |
| `wolf_auditor/reporting.py` | SARIF `artifacts[].hashes["sha-256"]` from `file_manifest` |
| `wolf_auditor/osv.py`, `policy.py`, `iac.py`, `delta.py`, `__main__.py` | Unchanged |
| `tests/test_p1_completion.py` | New tests. Old test files unchanged |
| `tests/fixtures/schemas/*.json` | Official schema bytes |
| `.gitattributes` | Those schema files stay LF |
| `.github/workflows/ci.yml` | Test-only `jsonschema==4.23.0` install |
| `docs/ARCHITECTURE.md` | P1 line updated to the implemented prototype and its limits |

## Feature inventory

| Feature | Phase | Classification | Evidence |
| --- | --- | --- | --- |
| Read-only scan, no target execution | P0 | IMPLEMENTED | `tests/test_engine.py` `test_no_external_execution_or_network` |
| File SHA-256 manifest and report hash | P0 | IMPLEMENTED | `engine.py` `file_manifest`; `delta.verify_report` used by the new evidence test |
| `INCOMPLETE` on symlink, size, parse, and budget stop | P0 / P1 | IMPLEMENTED | Existing symlink and size tests; new budget test |
| Python AST call rules | P1 | IMPLEMENTED | `analysis.python_sast`; old and new tests |
| Cargo.lock, package-lock.json, requirements.txt inventory | P1 | IMPLEMENTED | `supply_chain.inventory`; old tests plus v1 lock and broken Cargo tests |
| SARIF 2.1.0 | P1 | IMPLEMENTED | `reporting.to_sarif`; schema test, 0 errors on the fixture document |
| CycloneDX 1.6 | P1 | IMPLEMENTED | `reporting.to_sbom`; schema test, 0 errors on the fixture document |
| Independent schema check | P1 | IMPLEMENTED | jsonschema against the pinned official files. This is not an external audit firm |
| External adapters | outside P1 | MISSING | Not in this tree |
| Full language coverage | outside P1 | MISSING | `.js` fixture produces no finding and no gap |
| CVE completeness | outside P1 | MISSING | Optional OSV remains P1.5 and was not extended |
| OSV, policy, IaC, delta | P1.5 | IMPLEMENTED | Existing `tests/test_security_v03.py` still runs. Not modified |
| FFI, fuzzing, native Windows checks | P2 | MISSING | Not added |

## SAST / inventory / SBOM / SARIF matrix

| Rule or output | Positive fixture | Negative fixture | Limit |
| --- | --- | --- | --- |
| `PY_DYNAMIC_EXECUTION` | `eval`, `exec`, `builtins.eval` | string and comment `eval` in the old test | A function parameter named `eval` is still a call named `eval` |
| `PY_OS_SYSTEM` | `os.system`, `import os as`, `from os import system` | parameter or assignment named `system` | Function-local import alias is not resolved. Qualified `os.system` inside a function still matches |
| `PY_SHELL_TRUE` | keyword `shell=True`, including `import subprocess as sp` | `shell=False` | Positional `True` is not detected. Locked by test |
| `PY_UNSAFE_DESERIALIZATION` | `pickle.loads`, `marshal.load` | not applied to SQL or `open()` | `pickle.Unpickler` is not a separate rule |
| `PY_YAML_LOAD_REVIEW` | bare `yaml.load`, `Loader=yaml.FullLoader` | `yaml.safe_load`, `SafeLoader`, `CSafeLoader` | A custom class named `SafeLoader` would be treated as safe |
| Dependency inventory | pinned extra `requests[security]==2.31.0`, npm lock v1 nesting, Cargo package | broken Cargo clears that file's components and sets `dependency_manifest_parse_failed`; `-r` sets a gap | Not a vulnerability decision |
| SARIF | version `2.1.0`, artifact SHA-256, redacted message | version `0.0.0` is rejected by the OASIS schema | Schema success is structural |
| CycloneDX | `specVersion` `1.6`, components from the three manifests | `bomFormat` `not-a-bom` is rejected | The 1.6 schema types `specVersion` as a string and does not enum it. A wrong version string is not what the negative test uses |

## Schema results

Validator: `jsonschema.validators.validator_for` with `FORMAT_CHECKER`, versions above.

On a fixture that contains `os.system`, a Python syntax error, `Cargo.lock`, an npm lock, and `requirements.txt`:

- SARIF error count: 0
- CycloneDX error count: 0

The hashes are taken from `git cat-file blob` with `core.autocrlf=false`, not from the worktree file. Windows checkout of `5f13fd7` hashed the worktree and failed. See Actions below.

## Evidence integrity

For a finding, the new test checks:

- `path`, integer `line` >= 1, and `rule`
- `file_manifest[path].sha256` equals SHA-256 of the bytes read back from that path
- SARIF artifact `hashes["sha-256"]` equals that digest
- `verify_report` accepts `report_sha256`
- a second `scan` and a second SARIF/SBOM conversion compare equal

Source lines are not copied into the evidence or SARIF document. The existing secret tests still run.

## False positive and false negative examples

False positive removed: `yaml.load(data, Loader=yaml.SafeLoader)` no longer emits `PY_YAML_LOAD_REVIEW`. Before this branch the same call was flagged. Probe on the pre-change function returned two `PY_YAML_LOAD_REVIEW` hits for SafeLoader plus bare `yaml.load`.

False positive avoided: after `from os import system` and a later `system = print`, the call is not `PY_OS_SYSTEM`. A parameter named `system` is not treated as `os.system`.

False negatives locked, so they are not silent:

- `cursor.execute('SELECT ' + user)`, `open(path).read()`, `requests.get(url)` produce no findings.
- `app.js` containing `eval` is not scanned. `scanned_files` stays 0 for a tree that has only that file. Status becomes `NO_HEURISTIC_FINDINGS` when no recognized file produces a finding or a gap.
- `subprocess.run('echo x', None, None, None, True)` produces no `PY_SHELL_TRUE`.

## Trust boundaries

- Target files are read. The existing test writes `raise SystemExit` and the process still finishes.
- Symlinks are gaps, not followed.
- Secret-like values are not echoed. Evidence text is `heuristic_match_redacted`.
- `--osv-online` remains opt-in. This branch does not call it.
- Unrecognized extensions are not coverage gaps. That preserves the self-audit contract: exit 2 fails CI, and a README or schema JSON must not by itself make the repository scan `INCOMPLETE`. The status `NO_HEURISTIC_FINDINGS` is not a statement about unscanned languages.
- A stopped file budget now records both the file that crossed the budget and `scan_stopped_before_remaining_files`.

## Actions evidence

| Commit | Run | ubuntu-latest | windows-latest |
| --- | --- | --- | --- |
| `5f13fd7267158a37f879eb0f13ed72a9c034bb91` | https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38942330309 | success, https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38942330309/job/117112800468 | failure, https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38942330309/job/117112800460 |
| `71b60811515dc069f77478f26dc49914defbc09a` | https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38942520179 | success, https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38942520179/job/117113447867 | success, https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38942520179/job/117113447451 |

Windows failure on `5f13fd7`: `test_published_schemas_match_pinned_bytes_and_accept_output` compared worktree SHA-256 `96b31419a1c0faf5c57effaab4f5f5323fff114576c44e162b1b447b69aa85b8` with the LF schema hash. `test_evidence_joins_path_line_rule_and_source_hash` compared the manifest hash of the CRLF file written by `Path.write_text` with the LF string hash `8f83689af966dfa276d0e7e10f3040c7fda160eb47854d37da4aa53132e38261`.

On `71b6081`, both operating systems finished the unit-test step and the self-audit step with GitHub conclusion `success`. That means the executed checks completed. It does not certify the product.

No pull_request event exists for `71b6081` because the pull request was opened after that push. The pull request event runs on later commits. Those URLs are not claimed in this paragraph.

## Residuals and out of scope

Not blockers of the P1 gate:

- No SQL, XSS, SSRF, path traversal, or taint analysis.
- No JavaScript, Java, Go, or C parser.
- Positional `shell=True` and function-local import aliases are not resolved.
- Comments that start with `#` or `//` are skipped before the secret line scan.
- OSV is optional and fail-closed. It is not a complete CVE database.
- P2 and P3 from `docs/ARCHITECTURE.md` were not started.
- PR #4 authorization work is not in this branch. It was not regressed because this branch does not edit it.

## Blockers

None for the P1 gate. The earlier Windows job is a fixed test defect, not an open blocker.

## Re-check

- Pull request head SHA equals the commit being read.
- Ubuntu and Windows jobs for that head, including the documentation commit, finished.
- Root `LICENSE` is still absent.
- `main` is still `d5ffd6111ae5b495bc713b57b40ceba0266c2b08`.
- PR #4, PR #5, and PR #6 heads are unchanged.
- `tests/test_engine.py`, `tests/test_extended.py`, and `tests/test_security_v03.py` are still present.
