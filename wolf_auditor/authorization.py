"""Single-customer local scan scope. Not a security certification."""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

CUSTOMER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
COMMIT_SHA = re.compile(r"[0-9a-fA-F]{40}")
AUTH_SCHEMA = "wolf-auditor.customer-authorization.v1"
MAX_AUTH_BYTES = 65_536

NOT_CERTIFICATION = "This is not a security certification."
BOUND_DISCLAIMER = (
    "Bound to one authorized customer for a local read-only scan. " + NOT_CERTIFICATION
)
UNBOUND_DISCLAIMER = (
    "Local scan is not bound to an authorized customer. " + NOT_CERTIFICATION
)
COMMIT_NONE = "No commit claim was supplied. " + NOT_CERTIFICATION
COMMIT_REJECTED = "Unverified commit claims are rejected. " + NOT_CERTIFICATION
COMMIT_MATCH = "Local clean HEAD matched this commit. " + NOT_CERTIFICATION


class FileTooLarge(Exception):
    """Regular file exceeds the scan byte budget."""


class RejectedSymlink(OSError):
    """A symlink or non-regular file must not be read."""


def parse_single_customer(value: object) -> str:
    """Accept exactly one customer id. Reject lists, paths, and combined ids."""
    if not isinstance(value, str):
        raise ValueError("customer id rejected")
    if value != value.strip() or any(sep in value for sep in (",", " ", "\t", "\n", "/", "\\", "\x00")):
        raise ValueError("customer id rejected")
    if CUSTOMER_ID.fullmatch(value) is None:
        raise ValueError("customer id rejected")
    return value


def customer_scope(customer_id: str | None) -> dict[str, Any]:
    if customer_id is None:
        return {
            "schema": "wolf-auditor.customer-scope.v1",
            "bound": False,
            "customer_count": 0,
            "certification": False,
            "disclaimer": UNBOUND_DISCLAIMER,
        }
    return {
        "schema": "wolf-auditor.customer-scope.v1",
        "bound": True,
        "customer_id": customer_id,
        "customer_count": 1,
        "certification": False,
        "disclaimer": BOUND_DISCLAIMER,
    }


def load_customer_authorization(path: Path) -> str:
    """Read one customer id. Extra customers and symlink files are rejected."""
    path = Path(path)
    try:
        if path.is_symlink():
            raise ValueError("symlink authorization file rejected")
        blob = read_regular_file(path, MAX_AUTH_BYTES)
        data = json.loads(blob.decode("utf-8"))
    except FileTooLarge as error:
        raise ValueError("customer authorization rejected") from error
    except RejectedSymlink as error:
        if path.is_symlink():
            raise ValueError("symlink authorization file rejected") from error
        raise ValueError("customer authorization rejected") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("customer authorization rejected") from error
    if not isinstance(data, dict) or set(data) != {"schema", "customer_id"}:
        raise ValueError("customer authorization rejected")
    if data.get("schema") != AUTH_SCHEMA:
        raise ValueError("customer authorization rejected")
    return parse_single_customer(data.get("customer_id"))


def reject_symlink_path(path: Path) -> Path:
    """Resolve a directory without following any symlink component."""
    path = Path(path).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    current = Path(path.anchor)
    for part in path.parts[1:]:
        if part in ("", "."):
            continue
        if part == "..":
            if current == Path(current.anchor):
                raise ValueError("target must be an existing directory")
            current = current.parent
            continue
        current = current / part
        try:
            if current.is_symlink():
                raise ValueError("symlink path component rejected")
            if not current.exists():
                raise ValueError("target must be an existing directory")
        except OSError as error:
            raise ValueError("target must be an existing directory") from error
    if not current.is_dir():
        raise ValueError("target must be an existing directory")
    return current


def confine_target(target: Path, authorized_root: Path | None, customer_id: str | None) -> tuple[Path, dict[str, Any]]:
    """Bind a local directory to zero or one customer. Never follow a symlink root."""
    if authorized_root is not None and customer_id is None:
        raise ValueError("authorized root requires one customer id")
    checked_id = parse_single_customer(customer_id) if customer_id is not None else None
    root = reject_symlink_path(target)
    if authorized_root is not None:
        boundary = reject_symlink_path(authorized_root)
        try:
            root.relative_to(boundary)
        except ValueError:
            raise ValueError("target is outside the authorized customer root") from None
    return root, customer_scope(checked_id)


def read_regular_file(path: Path, limit: int) -> bytes:
    """Read a regular file. Symlink targets are not followed."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise RejectedSymlink(error.errno, "symlink target rejected") from error
        raise
    try:
        info = os.fstat(fd)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RejectedSymlink(errno.EINVAL, "symlink target rejected")
        if info.st_size > limit:
            raise FileTooLarge()
        blob = os.read(fd, limit + 1)
        if len(blob) > limit:
            raise FileTooLarge()
        return blob
    finally:
        os.close(fd)


def assess_commit_claim(root: Path, claim: str | None) -> tuple[dict[str, Any], bool]:
    """Reject any commit claim that is not this directory's clean local HEAD.

    A matching HEAD is still not a security certification. The supplied text is
    never copied into the report unless it is a confirmed 40-character object id.
    """
    if claim is None:
        return {
            "status": "not_claimed",
            "accepted": False,
            "verified": False,
            "certification": False,
            "disclaimer": COMMIT_NONE,
        }, False
    if not isinstance(claim, str) or COMMIT_SHA.fullmatch(claim) is None:
        return _rejected_commit(), True
    sha = claim.lower()
    if not _clean_local_head(root, sha):
        return _rejected_commit(), True
    return {
        "status": "local_head_match",
        "accepted": True,
        "verified": True,
        "certification": False,
        "commit": sha,
        "reason": "clean_local_head",
        "disclaimer": COMMIT_MATCH,
    }, False


def _rejected_commit() -> dict[str, Any]:
    return {
        "status": "rejected",
        "accepted": False,
        "verified": False,
        "certification": False,
        "reason": "unverified_commit_claim_rejected",
        "disclaimer": COMMIT_REJECTED,
    }


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(
        ["git", "-C", os.fspath(root), *args],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        stdin=subprocess.DEVNULL,
        env=env,
    )


def _clean_local_head(root: Path, sha: str) -> bool:
    try:
        kind = _git(root, "cat-file", "-t", sha)
        head = _git(root, "rev-parse", "--verify", "HEAD")
        status = _git(root, "status", "--porcelain")
        toplevel = _git(root, "rev-parse", "--show-toplevel")
    except (OSError, subprocess.TimeoutExpired):
        return False
    if kind.returncode != 0 or kind.stdout.strip() != "commit":
        return False
    if head.returncode != 0 or head.stdout.strip().lower() != sha:
        return False
    if status.returncode != 0 or status.stdout.strip() != "":
        return False
    if toplevel.returncode != 0:
        return False
    reported = toplevel.stdout.strip()
    try:
        return os.path.samefile(reported, root)
    except OSError:
        return os.path.normcase(os.path.normpath(reported)) == os.path.normcase(os.path.normpath(os.fspath(root)))
