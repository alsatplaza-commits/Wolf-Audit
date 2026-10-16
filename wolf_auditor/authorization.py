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


class OutsideHardlink(Exception):
    """A regular file has another directory entry outside the scan root."""


_REPARSE_POINT = 0x400


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


def has_reparse_attribute(attributes: int) -> bool:
    """Windows FILE_ATTRIBUTE_REPARSE_POINT covers junctions, symlinks, and mount points."""
    return bool(attributes & _REPARSE_POINT)


def is_unfollowed_link(path: Path) -> bool:
    """True for symlinks, junctions, and other reparse points. Unreadable entries fail closed."""
    try:
        if path.is_symlink():
            return True
    except OSError:
        return True
    checker = getattr(path, "is_junction", None)
    if checker is not None:
        try:
            if checker():
                return True
        except OSError:
            return True
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if has_reparse_attribute(getattr(info, "st_file_attributes", 0) or 0):
        return True
    return False


def inode_name_counts(root: Path) -> dict[tuple[int, int], int]:
    """Count regular-file names inside root without following links."""
    counts: dict[tuple[int, int], int] = {}
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = [name for name in dirnames if not is_unfollowed_link(Path(directory) / name)]
        for name in filenames:
            candidate = Path(directory) / name
            if is_unfollowed_link(candidate):
                continue
            try:
                info = candidate.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_ino == 0:
                continue
            key = (info.st_dev, info.st_ino)
            counts[key] = counts.get(key, 0) + 1
    return counts


def _json_object(blob: bytes) -> dict[str, Any]:
    """Parse one JSON object and reject duplicate keys instead of keeping the last."""
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in items:
            if key in obj:
                raise ValueError("customer authorization rejected")
            obj[key] = value
        return obj

    try:
        data = json.loads(blob.decode("utf-8"), object_pairs_hook=pairs)
    except ValueError as error:
        if str(error) == "customer authorization rejected":
            raise
        raise ValueError("customer authorization rejected") from error
    if not isinstance(data, dict):
        raise ValueError("customer authorization rejected")
    return data


def load_customer_authorization(path: Path) -> str:
    """Read one customer id. Extra customers and symlink files are rejected."""
    path = Path(path)
    if is_unfollowed_link(path):
        raise ValueError("symlink authorization file rejected")
    try:
        blob = read_regular_file(path, MAX_AUTH_BYTES)
        data = _json_object(blob)
    except FileTooLarge as error:
        raise ValueError("customer authorization rejected") from error
    except RejectedSymlink as error:
        raise ValueError("symlink authorization file rejected") from error
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("customer authorization rejected") from error
    if set(data) != {"schema", "customer_id"}:
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
            if is_unfollowed_link(current):
                raise ValueError("symlink path component rejected")
            if not current.exists():
                raise ValueError("target must be an existing directory")
        except OSError as error:
            raise ValueError("target must be an existing directory") from error
    if not current.is_dir():
        raise ValueError("target must be an existing directory")
    return current


def confine_target(
    target: Path,
    authorized_root: Path | None,
    customer_id: str | None,
) -> tuple[Path, Path | None, dict[str, Any]]:
    """Bind a local directory to zero or one customer. Never follow a symlink root.

    The returned boundary is the customer directory that evidence outputs must
    stay inside. An unbound scan has no boundary.
    """
    if authorized_root is not None and customer_id is None:
        raise ValueError("authorized root requires one customer id")
    checked_id = parse_single_customer(customer_id) if customer_id is not None else None
    root = reject_symlink_path(target)
    boundary: Path | None = None
    if authorized_root is not None:
        boundary = reject_symlink_path(authorized_root)
        try:
            root.relative_to(boundary)
        except ValueError:
            raise ValueError("target is outside the authorized customer root") from None
    elif checked_id is not None:
        boundary = root
    return root, boundary, customer_scope(checked_id)


def prepare_contained_path(path: Path, boundary: Path | None, *, kind: str) -> Path:
    """Lexical path with no symlink or junction component.

    When boundary is set, the path must stay inside that customer directory.
    """
    path = Path(path).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    parts = list(path.parts[1:])
    if not parts or parts[-1] in ("", ".", ".."):
        raise ValueError(f"{kind} path rejected")
    current = Path(path.anchor)
    for part in parts[:-1]:
        if part in ("", "."):
            continue
        if part == "..":
            if current == Path(current.anchor):
                raise ValueError(f"{kind} path rejected")
            current = current.parent
            continue
        current = current / part
        if is_unfollowed_link(current):
            raise ValueError(f"symlink {kind} path rejected")
        if current.exists() and not current.is_dir():
            raise ValueError(f"{kind} path rejected")
    final = current / parts[-1]
    if is_unfollowed_link(final):
        raise ValueError(f"symlink {kind} path rejected")
    if boundary is not None:
        try:
            final.relative_to(boundary)
        except ValueError:
            raise ValueError(f"{kind} path is outside the authorized customer root") from None
        if final == boundary:
            raise ValueError(f"{kind} path rejected")
    return final


def read_bounded_regular(path: Path, limit: int, *, kind: str) -> bytes:
    """Read a regular file. Symlink and junction inputs are not followed."""
    checked = prepare_contained_path(path, None, kind=kind)
    try:
        return read_regular_file(checked, limit)
    except FileTooLarge as error:
        raise ValueError(f"{kind} file exceeds limit") from error
    except RejectedSymlink as error:
        raise ValueError(f"symlink {kind} path rejected") from error


def write_contained_text(path: Path, text: str, boundary: Path | None) -> None:
    """Create or replace a regular file without following a symlink or junction."""
    final = prepare_contained_path(path, boundary, kind="output")
    _mkdir_contained(final.parent, boundary)
    if is_unfollowed_link(final):
        raise ValueError("symlink output path rejected")
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(final, flags, 0o600)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError("symlink output path rejected") from error
        raise
    try:
        info = os.fstat(fd)
        try:
            current = os.lstat(final)
        except OSError as error:
            raise ValueError("symlink output path rejected") from error
        if not os.path.samestat(info, current) or not stat.S_ISREG(info.st_mode):
            raise ValueError("symlink output path rejected")
        os.ftruncate(fd, 0)
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)


def _mkdir_contained(directory: Path, boundary: Path | None) -> None:
    current = Path(directory.anchor)
    for part in directory.parts[1:]:
        if part in ("", "."):
            continue
        current = current / part
        if is_unfollowed_link(current):
            raise ValueError("symlink output path rejected")
        if current.exists():
            if not current.is_dir():
                raise ValueError("output path rejected")
            continue
        if boundary is not None:
            try:
                current.relative_to(boundary)
            except ValueError:
                raise ValueError("output path is outside the authorized customer root") from None
        current.mkdir()
        if is_unfollowed_link(current) or not current.is_dir():
            raise ValueError("symlink output path rejected")


def read_regular_file(path: Path, limit: int, *, max_nlink: int | None = None) -> bytes:
    """Read a regular file. Symlink targets and outside hard links are not accepted."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise RejectedSymlink(error.errno, "symlink target rejected") from error
        raise
    try:
        info = os.fstat(fd)
        try:
            current = os.lstat(path)
        except OSError as error:
            raise RejectedSymlink(errno.ELOOP, "symlink target rejected") from error
        if (
            not os.path.samestat(info, current)
            or stat.S_ISLNK(current.st_mode)
            or has_reparse_attribute(getattr(current, "st_file_attributes", 0) or 0)
            or not stat.S_ISREG(info.st_mode)
        ):
            raise RejectedSymlink(errno.EINVAL, "symlink target rejected")
        if info.st_nlink > 1 and info.st_ino == 0:
            raise OutsideHardlink()
        if max_nlink is not None and info.st_nlink > max_nlink:
            raise OutsideHardlink()
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


def _index_hides_changes(listing: str) -> bool:
    """Reject assume-unchanged, skip-worktree, and any non-cached index flag."""
    for line in listing.splitlines():
        if line and line[0] != "H":
            return True
    return False


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run git without executing commands configured by the repository.

    A scan target is untrusted. core.fsmonitor and hooks in its config must
    not run while a commit claim is checked.
    """
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    locked = (
        "core.fsmonitor=",
        f"core.hooksPath={os.devnull}",
        "diff.external=",
        "credential.helper=",
        "protocol.file.allow=never",
        "protocol.ext.allow=never",
    )
    config: list[str] = []
    for item in locked:
        config.extend(("-c", item))
    return subprocess.run(
        ["git", "-C", os.fspath(root), *config, *args],
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
        status = _git(root, "status", "--porcelain=v1", "--ignored", "--untracked-files=all")
        flags = _git(root, "ls-files", "-v")
        sparse = _git(root, "config", "--local", "--get", "core.sparseCheckout")
        toplevel = _git(root, "rev-parse", "--show-toplevel")
    except (OSError, subprocess.TimeoutExpired):
        return False
    if kind.returncode != 0 or kind.stdout.strip() != "commit":
        return False
    if head.returncode != 0 or head.stdout.strip().lower() != sha:
        return False
    if status.returncode != 0 or status.stdout.strip() != "":
        return False
    if flags.returncode != 0 or _index_hides_changes(flags.stdout):
        return False
    if sparse.returncode == 0 and sparse.stdout.strip().lower() == "true":
        return False
    if toplevel.returncode != 0:
        return False
    reported = toplevel.stdout.strip()
    try:
        return os.path.samefile(reported, root)
    except OSError:
        return os.path.normcase(os.path.normpath(reported)) == os.path.normcase(os.path.normpath(os.fspath(root)))
