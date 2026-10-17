"""Language-neutral static analysis boundary.

The repository scan keeps its existing per-language calls. This registry is the
extension point for another language and does not make Rust the product model.
No stage compiles a crate, runs a build script, or expands a macro.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .analysis import python_sast
from .rust_safety import analyze_rust
from .windows_native import NATIVE_SUFFIXES, analyze_windows_source

Analyzer = Callable[[str, str], tuple[list[dict[str, Any]], list[dict[str, str]]]]

ANALYZERS: dict[str, Analyzer] = {
    ".rs": analyze_rust,
    ".py": python_sast,
}
ANALYZERS.update({suffix: analyze_windows_source for suffix in NATIVE_SUFFIXES})

PARSER_PLAN: tuple[dict[str, Any], ...] = (
    {
        "stage": "token_heuristic",
        "implemented": True,
        "compiles_source": False,
        "runs_build_scripts": False,
        "expands_macros": False,
        "evaluates_cfg": False,
        "resolves_names": False,
    },
    {
        "stage": "syntax_parser_no_expansion",
        "implemented": False,
        "candidates": ("syn", "rust-analyzer"),
        "compiles_source": False,
        "runs_build_scripts": False,
        "expands_macros": False,
        "reason": "Not integrated. A later parser must not compile the crate or run build scripts.",
    },
)


def registered_suffixes() -> tuple[str, ...]:
    return tuple(sorted(ANALYZERS))


def analyze_registered(path: str, content: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    analyzer = ANALYZERS.get(Path(path).suffix.lower())
    if analyzer is None:
        return [], [{"path": path, "reason": "language_analyzer_not_registered"}]
    return analyzer(path, content)
