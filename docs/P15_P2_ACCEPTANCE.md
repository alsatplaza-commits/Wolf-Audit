# P1.5 and P2 acceptance matrix

This matrix records what the current tests lock. It is not a security certification, not a CVE-complete review, and not independent human sign-off. Policy `PASS` means only that the automated gate's configured checks did not block.

Statuses used here:

- **Locked:** a named test fails if the behavior regresses.
- **INCOMPLETE:** the product records a coverage gap instead of a clean result.
- **HOLD:** a human decision or a capability that this prototype does not perform.

## P1.5

| Requirement | Result | Evidence |
| --- | --- | --- |
| Default scan does not query OSV | Locked | `test_osv_off_by_default`, `test_cli_without_osv_online_does_not_disclose` |
| `--osv-online` discloses package name, ecosystem, and exact version only | Locked | `test_cli_osv_online_is_explicit_and_sends_only_package_identity` |
| Comment text is not sent in the query | Locked | same CLI test |
| Matching advisory is review-level, not an exploit proof | Locked | `test_osv_real_advisory_shape_with_mock_no_network` |
| Empty OSV response is not certification | Locked | `test_osv_clean_response_is_not_security_certification` |
| Network error, timeout, malformed body, bad id, count mismatch | Locked, status `INCOMPLETE` | `test_osv_network_failure_incomplete_not_pass`, `test_osv_timeout_is_incomplete`, `test_osv_malformed_response_incomplete`, `test_osv_malformed_non_object_is_incomplete`, `test_osv_bad_advisory_id_rejected` |
| Partial querybatch | Locked, status `INCOMPLETE`, gate `BLOCK` | `test_osv_partial_batch_stays_incomplete` |
| Unpinned requirement is not looked up as a clean package | Locked, `INCOMPLETE` | `test_osv_unpinned_dependency_cannot_be_looked_up` |
| Strict policy rejects unknown keys, bad types, and incomplete evidence | Locked | `test_policy_typo_fails_configuration`, `test_policy_boolean_max_findings_rejected`, `test_invalid_policy_file_fails_closed`, `test_policy_blocks_incomplete_even_for_review_threshold` |
| Matched advisory blocks the default gate | Locked | `test_default_policy_blocks_matched_advisory_even_if_review_level` |
| IaC and secret indicators, values redacted | Locked | `test_terraform_public_acl_and_ingress`, `test_kubernetes_privilege_escalation`, `test_private_key_redaction`, `test_fake_github_token_not_exposed`, `test_potential_secret_is_never_in_report` |
| Delta refuses a tampered digest or a different target | Locked | `test_delta_reports_new_and_resolved_findings`, `test_delta_rejects_modified_evidence`, `test_delta_rejects_other_target` |
| SARIF and CycloneDX carry the advisory id, not source text | Locked | `test_sbom_contains_linked_osv_vulnerability`, `test_osv_partial_batch_stays_incomplete` |
| Real OSV corpus equals all applicable CVEs | HOLD | Not claimed. The disclaimer says a match is not a complete guarantee. |

## P2

| Requirement | Result | Evidence |
| --- | --- | --- |
| Rust comments and strings are not code | Locked | `test_rust_comment_unsafe_is_not_code`, `test_rust_string_ffi_text_is_not_code` |
| Real `unsafe` block is review, not an exploit | Locked | `test_real_unsafe_block_is_review_not_exploit` |
| `#[unsafe(no_mangle)]`, `extern "system"`, `extern "C"`, redacted symbol text | Locked | `test_unsafe_attribute_no_mangle`, `test_extern_system_boundary`, `test_rust_macro_boundaries_are_not_a_parser_pass`, `test_ffi_symbol_link_and_export_names_are_redacted` |
| `unsafe!` is not a silent clean result | Locked, `INCOMPLETE` | `test_rust_macro_boundaries_are_not_a_parser_pass` |
| `include!` hides unseen source | Locked, gap `rust_macro_not_expanded` | same test |
| Macro body tokens are inventoried; expansion and `cfg` evaluation are not | Locked as non-exploit inventory. Not a parser. | same test; `analysis_limits.rust_syntax` |
| Full Rust parser, name resolution, build-cfg reachability | HOLD | Out of scope. Do not read `REVIEW_REQUIRED` as compiler truth. |
| Windows API names in C/C++ comments and strings are ignored; real calls are classified | Locked | `test_windows_native_api_detection_ignores_comments_and_strings` |
| Runtime process inspection | HOLD, status `NOT_EXECUTED`, native files stay `INCOMPLETE` | `test_windows_runtime_is_not_pass_on_host`. The module does not open a process on Linux or Windows. |
| Fuzz seed, iteration, timeout, memory, crash, replay | Locked | `test_deterministic_fuzz_repeats_and_does_not_claim_coverage`, `test_non_bytes_seed_is_rejected`, `test_zero_and_negative_iterations_are_rejected`, `test_timeout_crash_and_memory_limit_are_distinct_and_replayable` |
| Repository scan does not execute the harness or the audited tree | Locked, `coverage_claim` false | `test_scan_does_not_execute_fuzz_harness`, `test_no_external_execution_or_network` |
| Fuzz of the audited program | HOLD | Not implemented. Running untrusted project code is outside this prototype. |
| Independent reviewer signature, `APPROVED`, or `REVIEWED` | HOLD | The gate disclaimer says it is not expert approval. |

Ubuntu and Windows job URLs belong to the commit that contains this file. They are recorded on the pull request and on issue #10 after that commit's checks finish. A green unit-test job is not a certification.
