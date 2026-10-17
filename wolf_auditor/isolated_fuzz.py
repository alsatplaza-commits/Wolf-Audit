"""Opt-in fuzz execution for one allowlisted static binary.

The default scan does not call this module. Nothing is executed unless
``enabled`` is exactly True, the target is a static ELF inside the allowlist,
and a private user/mount/network/pid namespace hides a host canary and blocks
a network socket. If that probe fails, the target is not started.

Reports store hashes and classifications only. Program output is discarded.
``coverage_claim`` is always false. Status is never PASS, REVIEWED, or APPROVED.
"""
from __future__ import annotations

import hashlib
import os
import random
import resource  # Imported before a sandbox unmounts the host filesystem.
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

_FORBIDDEN_STATUS = {"PASS", "REVIEWED", "APPROVED"}
_MAX_ITERATIONS = 8
_MAX_TIMEOUT_SECONDS = 5
_MAX_INPUT_BYTES = 64
_MEMORY_FLOOR = 32 * 1024 * 1024
_MAX_TARGET_BYTES = 2_000_000
_LIMITATION = "Isolated target execution is not fuzz coverage and is not a security certification."


def run_authorized_target(
    *,
    enabled: object = False,
    target: object = None,
    allowlist: object = None,
    seed: object = None,
    iterations: object = None,
    timeout_seconds: object = None,
    max_input_bytes: object = None,
    max_memory_bytes: object = None,
    corpus_dir: object = None,
    network: object = False,
) -> dict[str, Any]:
    if enabled is not True:
        return _result("NOT_EXECUTED", "opt_in_required", False, None)
    if network is True:
        return _result("BLOCK", "network_not_permitted", False, None)
    rejected = _validate(seed, iterations, timeout_seconds, max_input_bytes, max_memory_bytes)
    if rejected is not None:
        return rejected
    assert isinstance(seed, (bytes, bytearray))
    assert isinstance(iterations, int)
    assert isinstance(timeout_seconds, (int, float))
    assert isinstance(max_input_bytes, int)
    assert isinstance(max_memory_bytes, int)
    seed_bytes = bytes(seed)
    seed_hash = hashlib.sha256(seed_bytes).hexdigest()
    roots = _allowlist_roots(allowlist)
    if roots is None:
        return _result("BLOCK", "allowlist_rejected", False, seed_hash)
    resolved = _contained_file(target, roots)
    if resolved is None:
        return _result("BLOCK", "target_rejected", False, seed_hash)
    corpus = None
    if corpus_dir is not None:
        corpus = _contained_directory(corpus_dir, roots)
        if corpus is None:
            return _result("BLOCK", "corpus_rejected", False, seed_hash)
    if not _is_static_elf(resolved):
        return _result("INCOMPLETE", "dynamic_or_non_elf_target_not_isolated", False, seed_hash)
    if resolved.stat().st_size > _MAX_TARGET_BYTES:
        return _result("INCOMPLETE", "target_too_large", False, seed_hash)
    probe = probe_isolation()
    if not probe["available"]:
        return _result("INCOMPLETE", str(probe["reason"]), False, seed_hash, isolation=probe)
    payloads = planned_payloads(seed_bytes, iterations, max_input_bytes)
    replay: list[dict[str, Any]] = []
    status = "COMPLETE"
    reason = "target_finished"
    for index, payload in enumerate(payloads):
        kind, detail = _execute(resolved, payload, float(timeout_seconds), max_memory_bytes)
        if kind == "BLOCK":
            return _result("INCOMPLETE", detail, False, seed_hash, isolation=probe, replay=replay)
        replay.append({
            "index": index,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "classification": kind,
        })
        if corpus is not None:
            stored = corpus / f"{index}.payload"
            stored.write_bytes(payload.hex().encode("ascii"))
            os.chmod(stored, 0o600)
        if kind != "OK":
            status = kind
            reason = detail
            break
    return _result(status, reason, True, seed_hash, isolation=probe, replay=replay)


def planned_payloads(seed: bytes, iterations: int, max_input_bytes: int) -> list[bytes]:
    rng = random.Random()
    rng.seed(seed)
    payloads: list[bytes] = []
    for _ in range(iterations):
        length = rng.randrange(0, max_input_bytes + 1)
        payloads.append(bytes(rng.getrandbits(8) for _ in range(length)))
    return payloads


def probe_isolation() -> dict[str, Any]:
    if os.name != "posix" or shutil.which("unshare") is None:
        return _probe(False, "posix_namespace_unavailable")
    kind, detail = _namespace(mode="probe", payload=b"", timeout_seconds=5, memory_bytes=_MEMORY_FLOOR)
    if kind == "PROBE":
        return _probe(True, "namespace_probe_ok")
    return _probe(False, detail or "namespace_probe_failed")


def _probe(available: bool, reason: str) -> dict[str, Any]:
    return {
        "available": available,
        "network_isolated": available,
        "filesystem_isolated": available,
        "mechanism": "user_mount_net_pid" if available else None,
        "reason": reason,
    }


def _validate(
    seed: object,
    iterations: object,
    timeout_seconds: object,
    max_input_bytes: object,
    max_memory_bytes: object,
) -> dict[str, Any] | None:
    if not isinstance(seed, (bytes, bytearray)) or isinstance(seed, memoryview) or len(seed) == 0:
        return _result("INCOMPLETE", "invalid_seed", False, None)
    if isinstance(iterations, bool) or not isinstance(iterations, int) or not 0 < iterations <= _MAX_ITERATIONS:
        return _result("INCOMPLETE", "invalid_iterations", False, None)
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        return _result("INCOMPLETE", "invalid_timeout", False, None)
    if not 0 < float(timeout_seconds) <= _MAX_TIMEOUT_SECONDS:
        return _result("INCOMPLETE", "invalid_timeout", False, None)
    if isinstance(max_input_bytes, bool) or not isinstance(max_input_bytes, int) or not 0 < max_input_bytes <= _MAX_INPUT_BYTES:
        return _result("INCOMPLETE", "invalid_input_budget", False, None)
    if isinstance(max_memory_bytes, bool) or not isinstance(max_memory_bytes, int) or max_memory_bytes <= 0:
        return _result("INCOMPLETE", "invalid_memory_budget", False, None)
    if max_memory_bytes < _MEMORY_FLOOR:
        return _result("RESOURCE_LIMIT", "memory_limit_below_isolation_floor", False, None)
    return None


def _allowlist_roots(allowlist: object) -> list[Path] | None:
    if not isinstance(allowlist, (list, tuple)) or not allowlist:
        return None
    roots: list[Path] = []
    for item in allowlist:
        if not isinstance(item, (str, Path)):
            return None
        path = Path(item)
        if not path.is_absolute() or any(part == ".." for part in path.parts):
            return None
        if _symlink_component(path) or not path.is_dir():
            return None
        roots.append(path.resolve())
    return roots


def _contained_file(candidate: object, roots: list[Path]) -> Path | None:
    path = _contained_path(candidate, roots)
    if path is None or not path.is_file():
        return None
    return path


def _contained_directory(candidate: object, roots: list[Path]) -> Path | None:
    path = _contained_path(candidate, roots)
    if path is None or not path.is_dir():
        return None
    return path


def _contained_path(candidate: object, roots: list[Path]) -> Path | None:
    if not isinstance(candidate, (str, Path)):
        return None
    path = Path(candidate)
    if not path.is_absolute() or any(part == ".." for part in path.parts):
        return None
    if _symlink_component(path) or not path.exists():
        return None
    resolved = path.resolve()
    if not any(resolved.is_relative_to(root) for root in roots):
        return None
    return resolved


def _symlink_component(path: Path) -> bool:
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            return True
        if not cursor.exists():
            return False
    return False


def _is_static_elf(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            header = handle.read(64)
            if len(header) < 64 or header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
                return False
            phoff = struct.unpack_from("<Q", header, 32)[0]
            phentsize = struct.unpack_from("<H", header, 54)[0]
            phnum = struct.unpack_from("<H", header, 56)[0]
            if phnum > 128 or phentsize < 56 or phentsize > 1024:
                return False
            end = phoff + phentsize * phnum
            if end > _MAX_TARGET_BYTES:
                return False
            handle.seek(0)
            blob = handle.read(end)
        if len(blob) < end:
            return False
        for index in range(phnum):
            offset = phoff + index * phentsize
            if struct.unpack_from("<I", blob, offset)[0] == 3:
                return False
        return True
    except (OSError, struct.error):
        return False


def _classify_message(message: str, timed_out: bool) -> tuple[str, str]:
    tokens = message.split()
    if timed_out:
        if "started" in tokens:
            return "TIMEOUT", "target_timeout"
        return "BLOCK", "sandbox_timeout"
    if tokens[:2] == ["probe", "ok"]:
        return "PROBE", "namespace_probe_ok"
    if "exit" in tokens:
        index = tokens.index("exit")
        if index + 1 < len(tokens) and tokens[index + 1].isdigit():
            code = int(tokens[index + 1])
            if code == 0:
                return "OK", "target_exit_0"
            return "CRASH", "target_nonzero_exit"
    if "signal" in tokens:
        return "CRASH", "target_signal"
    if "block" in tokens:
        index = tokens.index("block")
        detail = tokens[index + 1] if index + 1 < len(tokens) else "sandbox_blocked"
        return "BLOCK", detail
    if not tokens:
        return "BLOCK", "sandbox_no_report"
    return "BLOCK", "sandbox_unrecognized"


def _execute(target: Path, payload: bytes, timeout_seconds: float, memory_bytes: int) -> tuple[str, str]:
    return _namespace(
        mode="exec",
        payload=payload,
        timeout_seconds=timeout_seconds,
        memory_bytes=memory_bytes,
        target=target,
    )


def _namespace(
    *,
    mode: str,
    payload: bytes,
    timeout_seconds: float,
    memory_bytes: int,
    target: Path | None = None,
) -> tuple[str, str]:
    jail = Path(tempfile.mkdtemp(prefix="wolf-jail-"))
    canary_dir = Path(tempfile.mkdtemp(prefix="wolf-canary-"))
    canary = canary_dir / "secret"
    read_fd: int | None = None
    write_fd: int | None = None
    try:
        canary.write_bytes(os.urandom(16))
        os.chmod(canary, 0o600)
        (jail / "old").mkdir()
        if mode == "exec":
            if target is None:
                return "BLOCK", "target_missing"
            work = jail / "work"
            work.mkdir()
            copied = work / "target"
            shutil.copyfile(target, copied)
            os.chmod(copied, 0o555)
        parent_ns = os.readlink("/proc/self/ns/mnt")
        read_fd, write_fd = os.pipe()
        os.set_inheritable(write_fd, True)
        package_root = str(Path(__file__).resolve().parents[1])
        command = [
            "unshare", "--user", "--map-root-user", "--mount", "--net", "--fork", "--pid", "--",
            sys.executable, "-c",
            "from wolf_auditor.isolated_fuzz import _sandbox_main; _sandbox_main()",
            parent_ns, str(jail), str(canary), str(write_fd), str(memory_bytes),
            str(max(1, int(timeout_seconds))), mode, payload.hex(),
        ]
        try:
            subprocess.run(
                command,
                check=False,
                timeout=timeout_seconds + 2 if mode == "exec" else timeout_seconds,
                capture_output=True,
                env={"WOLF_SANDBOX": "1", "PYTHONNOUSERSITE": "1", "PYTHONPATH": package_root},
                pass_fds=(write_fd,),
                close_fds=True,
            )
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
        os.close(write_fd)
        write_fd = None
        message = os.read(read_fd, 512).decode("ascii", "replace")
        return _classify_message(message, timed_out)
    finally:
        if write_fd is not None:
            os.close(write_fd)
        if read_fd is not None:
            os.close(read_fd)
        shutil.rmtree(jail, ignore_errors=True)
        shutil.rmtree(canary_dir, ignore_errors=True)


def _sandbox_main() -> None:
    """Run inside a new namespace. Refuse to touch the parent mount namespace."""
    if os.environ.get("WOLF_SANDBOX") != "1":
        raise SystemExit(2)
    parent_ns, jail, canary, fd_text, memory_text, cpu_text, mode, payload_hex = sys.argv[1:9]
    write_fd = int(fd_text)
    if write_fd < 3 or mode not in {"probe", "exec"}:
        raise SystemExit(2)
    if any(ch not in "0123456789abcdef" for ch in payload_hex) or len(payload_hex) > _MAX_INPUT_BYTES * 2:
        os.write(write_fd, b"block payload\n")
        return
    if os.readlink("/proc/self/ns/mnt") == parent_ns:
        os.write(write_fd, b"block namespace\n")
        return
    try:
        interfaces = Path("/proc/net/dev").read_text(encoding="ascii")
    except OSError:
        os.write(write_fd, b"block network\n")
        return
    names = [line.split(":", 1)[0].strip() for line in interfaces.splitlines() if ":" in line]
    if names != ["lo"]:
        os.write(write_fd, b"block network\n")
        return
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
    libc.mount.restype = ctypes.c_int
    libc.pivot_root.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    libc.pivot_root.restype = ctypes.c_int
    libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.umount2.restype = ctypes.c_int
    private = 16384 | (1 << 18)
    if libc.mount(b"none", b"/", None, private, None) != 0:
        os.write(write_fd, b"block mount\n")
        return
    encoded = jail.encode()
    if libc.mount(encoded, encoded, None, 4096, None) != 0:
        os.write(write_fd, b"block mount\n")
        return
    os.chdir(jail)
    if libc.pivot_root(b".", b"old") != 0:
        os.write(write_fd, b"block pivot\n")
        return
    if libc.umount2(b"/old", 2) != 0:
        os.write(write_fd, b"block umount\n")
        return
    if os.path.exists(canary):
        os.write(write_fd, b"block canary\n")
        return
    if mode == "probe":
        os.write(write_fd, b"probe ok\n")
        return
    os.write(write_fd, b"started\n")
    child = os.fork()
    if child == 0:
        os.close(write_fd)
        memory = int(memory_text)
        cpu = int(cpu_text)
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_NPROC, (8, 8))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1_048_576, 1_048_576))
        try:
            os.execv("/work/target", ["/work/target", payload_hex])
        except OSError:
            os._exit(127)
    _wait_child, status = os.waitpid(child, 0)
    if os.WIFEXITED(status):
        os.write(write_fd, f"exit {os.WEXITSTATUS(status)}\n".encode("ascii"))
        return
    if os.WIFSIGNALED(status):
        os.write(write_fd, f"signal {os.WTERMSIG(status)}\n".encode("ascii"))
        return
    os.write(write_fd, b"block wait\n")


def _result(
    status: str,
    reason: str,
    executed: bool,
    seed_hash: str | None,
    *,
    isolation: dict[str, Any] | None = None,
    replay: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if status in _FORBIDDEN_STATUS:
        status = "INCOMPLETE"
        reason = "false_pass_rejected"
    if executed and status == "INCOMPLETE" and reason.startswith("block"):
        executed = False
    return {
        "status": status,
        "coverage_claim": False,
        "executed": executed,
        "reason": reason,
        "isolation": isolation or _probe(False, "not_probed"),
        "seed_sha256": seed_hash,
        "replay": list(replay or []),
        "limitation": _LIMITATION,
    }
