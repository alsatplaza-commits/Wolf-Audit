# Wolf-Audit zero-regression integration audit

This record does not integrate the branches. It does not certify either branch. PASS, REVIEWED, and VERIFIED are not conclusions.

Integration decision: **BLOCKED**.

## Identity

| Item | Value |
| --- | --- |
| Repository | alsatplaza-commits/Wolf-Audit |
| `main` | `d5ffd6111ae5b495bc713b57b40ceba0266c2b08` |
| PR #4 | https://github.com/alsatplaza-commits/Wolf-Audit/pull/4 |
| PR #4 head | `e4d74128b0f93c86cc2fafa2d0781690957fb7b7` on `cursor/single-tenant-authorization-recovery` |
| PR #7 | https://github.com/alsatplaza-commits/Wolf-Audit/pull/7 |
| PR #7 head | `4be6d8ce208c65ca58e49763330a8bd2dd801d82` on `cursor/p1-completion-gate-31ed` |
| PR #5 head, not used | `63716997589cb7caafcb0389f9bbd0584639a18a` |
| PR #6 head, not used | `fb551c72472f7950a101e3be4f37f9a2ee7ed749` |
| This review branch | `cursor/zero-regression-integration-gate-31ed`, created from `main` |

No commit on PR #4, #5, #6, or #7 was added by this review. No merge and no cherry-pick was created.

## Commands

Read-only comparison from `/workspace` after `git fetch` of the five refs above:

```text
git diff --stat origin/main...origin/cursor/single-tenant-authorization-recovery
git diff --stat origin/main...origin/cursor/p1-completion-gate-31ed
git merge-tree --write-tree --name-only --messages \
  origin/cursor/single-tenant-authorization-recovery \
  origin/cursor/p1-completion-gate-31ed
```

`git merge-tree --write-tree` exit code: 1.

```text
CONFLICT (content): Merge conflict in wolf_auditor/engine.py
Auto-merging docs/ARCHITECTURE.md
Auto-merging wolf_auditor/engine.py
```

`docs/ARCHITECTURE.md` auto-merges. `wolf_auditor/engine.py` does not. The merged tree id printed before the conflict line was not checked out and was not committed.

A second, disposable `git merge-file -p` was run on copies under `/tmp/integ`. Those copies are not in the repository. Exit code for `engine.py`: 1. Exit code for `docs/ARCHITECTURE.md`: 0. The conflict markers were in the temporary copy only.

## What each side changes

PR #4 versus `main`: 12 files, +1396 / -26.

| Path | Role |
| --- | --- |
| `wolf_auditor/authorization.py` | New. One customer, symlink and hardlink rejection, commit claim, contained writes |
| `wolf_auditor/external_review.py` | New. Local packet intake. Cannot close review records |
| `wolf_auditor/engine.py` | `scan` gains keyword-only customer, root, and commit arguments. Default call still scans |
| `wolf_auditor/delta.py` | Refuses comparison across different bound customer ids |
| `wolf_auditor/__main__.py` | CLI flags and contained output writes |
| `tests/test_authorization.py` | New |
| `tests/test_external_review.py` | New |
| `tests/test_open_core_boundary.py` | New |
| `tests/test_security_v03.py` | Adds the signed-query redaction test |
| `README.md`, `SECURITY.md`, `docs/ARCHITECTURE.md` | Scope text |

PR #7 versus `main`: 11 files, +9848 / -21. Most of the addition is the two official schema fixtures.

| Path | Role |
| --- | --- |
| `wolf_auditor/analysis.py` | Import aliases, safe YAML loader exception, `marshal.load`, `builtins.eval` |
| `wolf_auditor/engine.py` | After a stopped walk, gap `scan_stopped_before_remaining_files` |
| `wolf_auditor/reporting.py` | SARIF artifact SHA-256 from `file_manifest` |
| `tests/test_p1_completion.py` | New |
| `tests/fixtures/schemas/*.json` | Official SARIF and CycloneDX schemas |
| `.gitattributes`, `.github/workflows/ci.yml` | LF schema files; test-only `jsonschema==4.23.0` |
| `docs/ARCHITECTURE.md`, two P1 reports | P1 wording and evidence |

## Overlap

| Path | main | PR #4 | PR #7 | Merge-tree |
| --- | --- | --- | --- | --- |
| `wolf_auditor/engine.py` | base | customer scope and file-read confinement | three-line budget gap | content conflict |
| `docs/ARCHITECTURE.md` | base | P3, customer, external review, Open Core lines | P1 sentence | auto-merge, not committed |
| Every other product file | one side or neither | no second editor | no second editor | would come from the side that changed it |

`analysis.py`, `reporting.py`, `authorization.py`, `external_review.py`, `delta.py`, and `__main__.py` are not two-sided conflicts. They are still not integrated, because the engine conflict blocks the tree.

## Conflict

Both sides insert different statements after the same `if stopped: break` in `scan`. Temporary `merge-file` markers, not applied:

```text
<<<<<<< PR #4 engine.py
    commit_record, commit_rejected = assess_commit_claim(root, commit_claim)
    if commit_rejected:
        gaps.append({"path": "<commit>", "reason": "unverified_commit_claim_rejected"})
=======
    if stopped:
        gaps.append({"path": "<scan>", "reason": "scan_stopped_before_remaining_files"})
>>>>>>> PR #7 engine.py
```

Keeping only the first block drops the budget-stop gap. Keeping only the second block drops unverified-commit rejection and, if the whole PR #7 file were taken, also drops customer scope. Keeping both texts was not done. That would be a manual conflict resolution, and the combined tests were not run.

The architecture auto-merge keeps the PR #7 P1 sentence and the PR #4 P3, customer, external-review, and Open Core sentences. It was inspected in `/tmp` and not written into a branch.

## Preservation matrix

| Behavior | Where it lives now | Lost if the other engine file wins | Required regression if a later merge exists |
| --- | --- | --- | --- |
| Unbound `scan(root)` | both | no, PR #4 arguments are keyword-only with defaults | `tests/test_engine.py` |
| One customer directory | PR #4 | yes | `tests/test_authorization.py` |
| Symlink and outside hardlink rejection | PR #4 | yes | `tests/test_authorization.py`, `tests/test_engine.py` |
| Unverified commit claim | PR #4 | yes | `tests/test_authorization.py` |
| Credential query redacted | PR #4 | yes | `test_signed_url_query_is_flagged_and_not_copied` |
| Cross-customer delta refusal | PR #4 `delta.py` | only if that file is omitted | `tests/test_authorization.py` |
| External review cannot close records | PR #4 | only if that module is omitted | `tests/test_external_review.py` |
| Open-core import boundary | PR #4 | only if that test is omitted | `tests/test_open_core_boundary.py` |
| Safe YAML loader not flagged | PR #7 `analysis.py` | only if `analysis.py` stays at `main` | `tests/test_p1_completion.py` |
| Budget-stop gap | PR #7 `engine.py` | yes, this is inside the conflict | `test_file_budget_records_that_the_walk_stopped` |
| SARIF artifact SHA-256 | PR #7 `reporting.py` | only if reporting stays at `main` or PR #4 | schema and evidence tests |
| CycloneDX 1.6 schema check | PR #7 | only if the new test and schemas are omitted | `tests/test_p1_completion.py` |
| `INCOMPLETE` on parse, size, symlink, bad lock | `main`, both PRs | not removed by either diff | existing incomplete tests |
| Read-only, no target execution | `main`, both PRs | not removed | `test_no_external_execution_or_network` |
| P1.5 OSV, policy, IaC | `main`, both PRs | PR #4 edits one security test by addition | `tests/test_security_v03.py` |

No proven defect required an edit on this review branch. No function was changed.

## Reference CI

These runs are for the separate heads. They are not an integrated run. Each listed workflow has Ubuntu and Windows jobs, and both jobs have GitHub conclusion `success`.

| Tree | Tests present | Push | Pull request |
| --- | --- | --- | --- |
| `main` `d5ffd61` | 57 | https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38902418561 | none on this SHA |
| PR #4 `e4d7412` | 102 | https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38929625711 | https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38929631646 |
| PR #7 `4be6d8c` | 66 | https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38942860383 | https://github.com/alsatplaza-commits/Wolf-Audit/actions/runs/38942867727 |

Test counts are `git grep -h "def test_" <ref> -- tests | wc -l`. The counts were not produced by one combined process.

## Not run

- The union of the 102 PR #4 tests and the 66 PR #7 tests on one tree.
- Customer-isolation, symlink, file-hash, SARIF, SBOM, and authorization negative tests on an integrated tree.
- Ubuntu and Windows Actions for an integrated tree.
- A resolved `engine.py`.

This documentation branch, after it is pushed, runs the `main` suite only. That run does not close the integration gate.

## Blockers

| Id | Why it blocks |
| --- | --- |
| I1 | `wolf_auditor/engine.py` has a content conflict. Automatic resolution is refused. |
| I2 | No integrated tree exists, so feature-loss and interaction claims would be untested. |
| I3 | `analysis.py` from PR #7 would change AST results under PR #4's scanner. That interaction was not executed. |

## Later step, not done here

A future change can be considered only when a human-resolved `engine.py` keeps both insertions, the rest of each side is taken without dropping unique files, and the combined tests finish on Ubuntu and Windows. This document is not that change.

## Re-check

- PR #4, #5, #6, and #7 heads are unchanged.
- `main` is unchanged.
- This branch contains the two integration reports and no product-code diff.
- Root `LICENSE` is absent.
