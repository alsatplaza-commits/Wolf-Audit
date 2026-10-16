# Wolf-Audit license technical audit

Independent engineering record for a later reviewer. This document is not a legal opinion, a clearance, or a certification. Words PASS, REVIEWED, and VERIFIED are not used as conclusions.

Posture of the public grant: **BLOCKED**.

## Repository identity

| Item | Value | Evidence |
| --- | --- | --- |
| Repository | alsatplaza-commits/Wolf-Audit | `gh repo view` |
| Public | true | GitHub repository metadata |
| Default branch | main | GitHub repository metadata |
| Base SHA audited for distribution | `d5ffd6111ae5b495bc713b57b40ceba0266c2b08` | `git rev-parse origin/main` on 2026-10-16 |
| Audit branch | `cursor/apache-license-audit-31ed` | created from that base; does not update PR #4 or PR #5 |
| PR #4 head, not modified by this work | `e4d74128b0f93c86cc2fafa2d0781690957fb7b7` | open, not draft, base main |
| PR #5 head, not modified by this work | `63716997589cb7caafcb0389f9bbd0584639a18a` | draft, base `wolf-music-downloads` |
| Enterprise repository | not found | `gh repo view alsatplaza-commits/Wolf-Audit-Enterprise` returned not found |
| GitHub license metadata on main | null | observed before this branch; this branch does not add a root `LICENSE` |

The commit SHA that adds this report, the pull request URL, and the Actions run URLs are written in the pull request description after the branch is pushed. They are not invented here. A reviewer must confirm the PR head SHA matches the blob they are reading.

## Scope

Included:

- Every file tracked on `origin/main` at `d5ffd6111ae5b495bc713b57b40ceba0266c2b08` (4 commits, 21 files).
- The additional paths present only on PR #4, for provenance, without merging that PR.
- Presence or absence of `*.apk` on `main`, on PR #4, and on `wolf-music-downloads`.

Not included:

- Line-by-line audit of setuptools or GitHub Action source. Those projects were not vendored.
- A global code-similarity search against the public internet. No such tool was run.
- A legal ownership determination.

`git rev-list --count origin/main` = 4. `git rev-list --count origin/main..origin/wolf-music-downloads` = 40. Those 40 commits are not ancestors of main.

## Tools and versions

| Tool | Result |
| --- | --- |
| ScanCode Toolkit | 32.5.0 started. Output format 4.1.0. SPDX License List 3.27. |
| pluggy | 1.5.0 was required. pluggy 1.7 raised `ValueError: did not find any 'pre_scan' hooks` and did not scan. |
| spdx_tools | 0.8.2, installed as a ScanCode dependency. Import succeeded. No SPDX document exists in the repository, so no document validation was run. |
| license_expression | Installed with ScanCode. Version attribute was not present; no version number is claimed. |
| reuse, licensee, fossology, askalono, nomos | Not on `PATH`. Not run. No results from them. |
| curl | Fetched the official license and the SPDX and PyPI JSON records below. |
| GitHub API | `repos/actions/checkout/license` and `repos/actions/upload-artifact/license`. |

ScanCode command, from the main worktree, after the official text file existed but excluding it:

```text
PYTHONPATH=/tmp/scancode-pkgs python3 /tmp/scancode-pkgs/bin/scancode \
  --license --copyright --json-pp /tmp/wolf-scancode-core.json --processes 1 \
  wolf_auditor tests docs/ARCHITECTURE.md policies README.md SECURITY.md \
  pyproject.toml .github .gitignore
```

Result: 37 files, 0 errors, license detections 0, copyright notices 0.

A second command that included `docs/licensing/APACHE-2.0.OFFICIAL.txt` reported one `apache-2.0` detection on that reference file and 0 copyright notices. That detection is the reference copy, not a project grant.

Official text command:

```text
curl -fsSL -o LICENSE-2.0.txt https://www.apache.org/licenses/LICENSE-2.0.txt
```

SHA-256: `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`. Size: 11358 bytes. The committed file `docs/licensing/APACHE-2.0.OFFICIAL.txt` is that byte string.

SPDX record command:

```text
curl -fsSL -o Apache-2.0.json https://spdx.org/licenses/Apache-2.0.json
```

Observed fields: `licenseId` Apache-2.0, `isOsiApproved` true, `isFsfLibre` true. `seeAlso` lists `https://www.apache.org/licenses/LICENSE-2.0` and `https://opensource.org/license/apache-2.0`.

## Dependency inventory

Runtime Python dependencies in `pyproject.toml`: none. The file has no `dependencies` table and no `license` field.

| Component | How it appears | License evidence | In the distributed tree? | Classification |
| --- | --- | --- | --- | --- |
| setuptools >=70 | `[build-system] requires` | PyPI JSON for release 84.0.0, field `license_expression`: MIT. Source not read. | No | METADATA_ONLY |
| actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 | `.github/workflows/ci.yml` | GitHub license API: MIT | No, not vendored | METADATA_ONLY |
| actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 | `.github/workflows/ci.yml` | GitHub license API: MIT | No, not vendored | METADATA_ONLY |
| Wolf-Music APKs | `wolf-music-downloads` only | No LICENSE file on that branch was established as a grant for the APKs | Not on main, not on PR #4 | OWNERSHIP_UNKNOWN |

No `vendor/`, wheel, or copied third-party package directory is tracked on main.

## File-level findings

Commit author is not a legal owner. Source URL means an upstream project URL found inside the file or by a code-match tool. None was found. Recommended action for every row is: do not add a copyright line until a holder is identified.

| Path | Introducing commit | Commit author | Source URL | Evidence | Risk | Action |
| --- | --- | --- | --- | --- | --- | --- |
| README.md | `5a915a1597a5a56155bdfacf9dc418e31dbd1eba` | alsatplaza-commits | none found | States that no open-source license is selected | High, blocker for a grant | Keep that sentence until a real grant |
| .github/workflows/ci.yml | `1b35ba17c9b2961442a955b03d0f561c8f9a45b0` | alsatplaza-commits | none found | No copyright header. ScanCode detection empty | High, ownership unknown | Do not invent a header |
| .gitignore | same `1b35ba17` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| SECURITY.md | same `1b35ba17` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| docs/ARCHITECTURE.md | same `1b35ba17` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| pyproject.toml | same `1b35ba17` | alsatplaza-commits | none found | No license field | High, ownership unknown | Do not add SPDX grant yet |
| tests/test_engine.py | same `1b35ba17` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| wolf_auditor/__init__.py | same `1b35ba17` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| wolf_auditor/__main__.py | same `1b35ba17` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| wolf_auditor/engine.py | same `1b35ba17` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| tests/test_extended.py | `2c27db5f4f3b168e84c94acbdb5d2bafbf3cc24e` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| wolf_auditor/analysis.py | same `2c27db5` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| wolf_auditor/reporting.py | same `2c27db5` | alsatplaza-commits | none found | CycloneDX has no license field | High, ownership unknown | Do not invent a header |
| wolf_auditor/supply_chain.py | same `2c27db5` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| policies/high-risk.json | `d5ffd6111ae5b495bc713b57b40ceba0266c2b08` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| policies/osv-required.json | same `d5ffd611` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| tests/test_security_v03.py | same `d5ffd611` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| wolf_auditor/delta.py | same `d5ffd611` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| wolf_auditor/iac.py | same `d5ffd611` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| wolf_auditor/osv.py | same `d5ffd611` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |
| wolf_auditor/policy.py | same `d5ffd611` | alsatplaza-commits | none found | No copyright header | High, ownership unknown | Do not invent a header |

PR #4 paths that are not on main. They are not in this branch's tree. Author is commit metadata only.

| Path | Introducing commit | Commit author | Source URL | Evidence | Risk | Action |
| --- | --- | --- | --- | --- | --- | --- |
| wolf_auditor/authorization.py | `547506c297771a86bb97c4e5537ae8ed749f0eb8` | Cursor Agent | none found | Agent commit is not ownership | High | Human authority required before a grant covers it |
| tests/test_authorization.py | same `547506c` | Cursor Agent | none found | Agent commit is not ownership | High | Same |
| wolf_auditor/external_review.py | `b80fb196ca6117645945bbec387ccfaa05c0af6a` | Cursor Agent | none found | Agent commit is not ownership | High | Same |
| tests/test_external_review.py | same `b80fb19` | Cursor Agent | none found | Agent commit is not ownership | High | Same |
| tests/test_open_core_boundary.py | `e4d74128b0f93c86cc2fafa2d0781690957fb7b7` | Cursor Agent | none found | Agent commit is not ownership | High | Same |

`wolf-music-release-bot` commits are on `wolf-music-downloads`, not on main. They are not ownership evidence.

## Ownership gaps

- No copyright assignment, CLA, or employer disclaimer is in the repository.
- The Git author `alsatplaza-commits <alsatplaza@gmail.com>` is an account identity, not a legal holder.
- Cursor Agent commits must not be counted as the holder.
- Patent position: no evidence. UNKNOWN.
- Trademark or logo registration: no evidence. UNKNOWN. A software license does not assign brand rights.
- Holder name, year, and patent language were not invented in NOTICE.

## Apache-2.0 matrix

| Question | Evidence | Result |
| --- | --- | --- |
| Official text available and hashed | apache.org file, SHA-256 above | Text is stored for review |
| SPDX identifier Apache-2.0 exists and is OSI-approved | SPDX JSON | Identifier is real |
| Project applies that identifier | No root LICENSE, no pyproject license, no SPDX header, README says none selected | Grant is absent. BLOCKED |
| NOTICE required by Apache for this tree | Apache requires preserving a NOTICE if the work has one. This tree has no in-force NOTICE | Draft only |
| Attribution for vendored code | No vendored source found | No attribution list to publish |
| MIT metadata for setuptools and the two actions | PyPI and GitHub license API | Not a reason to grant Apache on Wolf-Audit |
| GPL-2.0-only code combined into an Apache grant | No such code found in tree. Test fixture labels `GPL-2.0-only` as `LICENSE_CONFLICT_CANDIDATE` | No combined GPL-2.0-only tree was found |
| Agent or bot as licensor | Commit metadata only | Not accepted |

## Security and supply chain

- CI permissions on main are `contents: read`. This audit did not change that workflow.
- `--osv-online` remains opt-in in the engine. This audit did not change the engine.
- The signed object URL previously observed on `wolf-music-downloads` is outside main and outside this branch. PR #5 remains the separate draft that removes the fetch. This audit does not repeat that URL.
- Public CI artifacts of a self-audit are not customer evidence. This change does not add a customer scan.
- No new runtime dependency was added. ScanCode was installed under `/tmp` and is not a project dependency.

## Files added

- `docs/LICENSE_OWNER_REPORT_TR.md`
- `docs/LICENSE_TECHNICAL_AUDIT.md`
- `docs/licensing/STATUS.md`
- `docs/licensing/APACHE-2.0.OFFICIAL.txt`
- `docs/licensing/NOTICE.DRAFT.txt`
- `docs/licensing/THIRD_PARTY_NOTICES.DRAFT.txt`
- `tests/test_license_posture.py`

Not added: root `LICENSE`, in-force NOTICE, SPDX grant, Enterprise code, scanner behavior changes.

## Tests

Command:

```text
python3 -m unittest discover -s tests -v
```

The numeric result is recorded in the pull request after the command is run in this worktree. The new tests assert:

- official file hash
- a one-byte change does not match
- root license grant absent
- no SPDX grant in `wolf_auditor/*.py`
- drafts contain NOT IN FORCE and UNKNOWN, and do not contain PASS, REVIEWED, or VERIFIED
- empty license id -> OWNERSHIP_UNKNOWN
- `GPL-2.0-only` -> LICENSE_CONFLICT_CANDIDATE
- `MIT` -> METADATA_ONLY
- `scan()` still returns `wolf-auditor.evidence.v1` and has no `license_grant`

Ubuntu and Windows Actions URLs: not claimed until the run for this commit finishes. See the pull request description.

## Blockers

| Id | Severity | Blocker | What would move it |
| --- | --- | --- | --- |
| B1 | High | Copyright holder is UNKNOWN | Named person or company plus a written authority statement |
| B2 | High | Licensing authority for human and agent commits is UNKNOWN | Same statement, explicitly covering PR #4 agent lines before those lines are included in a grant |
| B3 | Medium | Patent grant inside Apache-2.0 cannot be made for an unknown holder | Holder states whether any patent is asserted |
| B4 | Medium | Trademark and logo rights are UNKNOWN and are separate from copyright | Holder states brand position; do not put brand rights inside the software license |
| B5 | Medium | APKs on `wolf-music-downloads` have UNKNOWN copyright and sit in the same public repository | Keep them out of Core; decide their distribution separately |
| B6 | Low | setuptools and Actions license evidence is repository metadata only | Acceptable while they stay unvendored; re-check if source is copied in |
| B7 | Low | The official Apache text in `docs/licensing/` can be mistaken for a grant | `STATUS.md` says NOT IN FORCE; root LICENSE stays absent |

## Re-check after this review

- PR head SHA equals the commit the reviewer read.
- Root `LICENSE` still absent on that SHA.
- `tests/test_license_posture.py` result on both ubuntu-latest and windows-latest.
- PR #4 and PR #5 heads unchanged: `e4d74128b0f93c86cc2fafa2d0781690957fb7b7` and `63716997589cb7caafcb0389f9bbd0584639a18a`.
- main still `d5ffd6111ae5b495bc713b57b40ceba0266c2b08` until a human merge, which this work does not do.
