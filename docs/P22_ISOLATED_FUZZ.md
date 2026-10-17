# P2.2 isolated target fuzzing

`run_authorized_target` is not used by the repository scan. A call executes a target only when all of the following are true:

- `enabled` is the boolean `True`
- `network` is not requested
- seed, iteration, timeout, input, and memory budgets are inside fixed limits
- the target path is an existing regular file inside an absolute allowlist directory, with no `..` component and no symlink component
- the target is a static ELF (no program interpreter). Scripts and dynamic binaries are not started
- a private user, mount, network, and pid namespace hides a host canary and cannot open a UDP socket

If any isolation check fails, the status is `INCOMPLETE` or `BLOCK`, `executed` is false, and the target is not started. Windows runners do not have this namespace mechanism, so they stay fail-closed.

A completed run is `COMPLETE`, not `PASS`. Crash, timeout, and a memory budget below the isolation floor are separate statuses. The report stores seed and payload hashes plus those classifications. Child output, the parent environment, and payload bytes are not copied into the report. `coverage_claim` is false: this is not coverage of an audited tree and not a certification.

Independent human approval remains HOLD. A runner without `unshare` or without a static ELF fixture cannot produce a successful execution result.
