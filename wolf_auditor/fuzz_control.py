"""Bounded fuzz harness for a caller-supplied callable.

The repository scanner does not call this module. A run that does not invoke a
callable is not fuzz coverage. Even a completed run only exercised the callable
the caller passed; it is not coverage of an audited tree.
"""
from __future__ import annotations

import hashlib
import random
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any, Callable

Target = Callable[[bytes], Any]


def run_controlled_fuzz(
    target: Target | None,
    *,
    seed: object,
    iterations: object,
    timeout_seconds: object,
    max_input_bytes: object,
    max_memory_bytes: object = None,
) -> dict[str, Any]:
    rejected = _validate(seed, iterations, timeout_seconds, max_input_bytes, max_memory_bytes)
    if rejected is not None:
        return rejected
    assert isinstance(seed, (bytes, bytearray))
    assert isinstance(iterations, int)
    assert isinstance(timeout_seconds, (int, float))
    assert isinstance(max_input_bytes, int)
    seed_bytes = bytes(seed)
    memory_limit = max_memory_bytes if isinstance(max_memory_bytes, int) else None
    if target is None or not callable(target):
        return _result(
            "NOT_EXECUTED",
            False,
            0,
            iterations,
            [],
            seed_bytes,
            "No callable was executed. This is not fuzz coverage.",
        )
    rng = random.Random()
    rng.seed(seed_bytes)
    failures: list[dict[str, Any]] = []
    ran = 0
    status = "COMPLETE"
    for index in range(iterations):
        length = rng.randrange(0, max_input_bytes + 1)
        payload = bytes(rng.getrandbits(8) for _ in range(length))
        if len(payload) > max_input_bytes:
            status = "RESOURCE_LIMIT"
            failures.append(_failure(index, seed_bytes, payload, "RESOURCE_LIMIT", None))
            break
        kind, exc_name = _invoke(target, payload, float(timeout_seconds), memory_limit)
        ran += 1
        if kind != "OK":
            status = kind
            failures.append(_failure(index, seed_bytes, payload, kind, exc_name))
            break
    return _result(
        status,
        False,
        ran,
        iterations,
        failures,
        seed_bytes,
        "Callable-only harness. Audited repository code is not executed. "
        "tracemalloc is not process RSS. A timeout does not prove the worker stopped. "
        "coverage_claim is false: this is not fuzz coverage of a target program.",
    )


def _validate(
    seed: object,
    iterations: object,
    timeout_seconds: object,
    max_input_bytes: object,
    max_memory_bytes: object,
) -> dict[str, Any] | None:
    if isinstance(seed, (bytes, bytearray)):
        if len(seed) == 0:
            return _invalid("INVALID_SEED", "empty bytes seed is rejected")
    else:
        return _invalid("INVALID_SEED", f"seed type {type(seed).__name__} is not bytes")
    if isinstance(iterations, bool) or not isinstance(iterations, int):
        return _invalid("INVALID_LIMIT", "iterations must be a non-bool int")
    if iterations == 0:
        return _invalid("INVALID_LIMIT", "zero iterations are rejected")
    if iterations < 0:
        return _invalid("INVALID_LIMIT", "negative iterations are rejected")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        return _invalid("INVALID_LIMIT", "timeout_seconds must be positive")
    if isinstance(max_input_bytes, bool) or not isinstance(max_input_bytes, int) or max_input_bytes <= 0:
        return _invalid("INVALID_LIMIT", "max_input_bytes must be positive")
    if max_memory_bytes is not None and (
        isinstance(max_memory_bytes, bool) or not isinstance(max_memory_bytes, int) or max_memory_bytes <= 0
    ):
        return _invalid("INVALID_LIMIT", "max_memory_bytes must be positive when set")
    return None


def _invoke(
    target: Target,
    payload: bytes,
    timeout_seconds: float,
    max_memory_bytes: int | None,
) -> tuple[str, str | None]:
    pool = ThreadPoolExecutor(max_workers=1)

    def call() -> None:
        if max_memory_bytes is None:
            target(payload)
            return
        tracemalloc.start()
        try:
            target(payload)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        if peak > max_memory_bytes:
            raise MemoryError("traced python allocation exceeded max_memory_bytes")

    future = pool.submit(call)
    try:
        future.result(timeout=timeout_seconds)
    except FutureTimeout:
        return "TIMEOUT", None
    except MemoryError:
        return "RESOURCE_LIMIT", "MemoryError"
    except Exception as error:
        return "CRASH", type(error).__name__
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return "OK", None


def _failure(
    iteration: int,
    seed: bytes,
    payload: bytes,
    kind: str,
    exception_type: str | None,
) -> dict[str, Any]:
    return {
        "iteration": iteration,
        "kind": kind,
        "exception_type": exception_type,
        "seed_sha256": hashlib.sha256(seed).hexdigest(),
        "input_sha256": hashlib.sha256(payload).hexdigest(),
        "input_hex": payload.hex(),
    }


def _invalid(status: str, reason: str) -> dict[str, Any]:
    return _result(status, False, 0, 0, [], b"", reason)


def _result(
    status: str,
    coverage_claim: bool,
    ran: int,
    requested: int,
    failures: list[dict[str, Any]],
    seed: bytes,
    limitation: str,
) -> dict[str, Any]:
    if status == "PASS" or coverage_claim:
        status = "NOT_EXECUTED"
        coverage_claim = False
        limitation = "fuzz coverage success was rejected"
    return {
        "status": status,
        "coverage_claim": coverage_claim,
        "callable_invoked": ran > 0,
        "iterations_requested": requested,
        "iterations_run": ran,
        "failures": failures,
        "seed_sha256": hashlib.sha256(seed).hexdigest() if seed else None,
        "limitation": limitation,
    }
