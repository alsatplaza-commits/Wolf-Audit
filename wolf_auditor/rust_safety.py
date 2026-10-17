"""Rust unsafe and FFI inventory using a token heuristic.

This is not a Rust parser. Macros, cfg-stripped code, and some literal forms
can be missed. Unclosed comments, strings, or attributes become coverage gaps
and are never reported as a clean result. Comment and string text is not code.
"""
from __future__ import annotations

from typing import Any

from .analysis import finding

_UNSAFE_FOLLOW = {"fn", "impl", "trait", "extern"}
_RISKY_TAIL = {
    ("transmute",),
    ("ptr", "read"),
    ("ptr", "write"),
    ("ptr", "read_unaligned"),
    ("ptr", "write_unaligned"),
    ("ptr", "read_volatile"),
    ("ptr", "write_volatile"),
    ("ptr", "copy"),
    ("ptr", "copy_nonoverlapping"),
    ("from_raw_parts",),
    ("from_raw_parts_mut",),
}
_SYMBOL_ATTRS = {"no_mangle", "export_name", "link_name"}
# Attribute names this heuristic can classify without running a macro.
# derive and cfg_attr are intentionally absent.
_RESOLVED_ATTRIBUTE_HEADS = {
    "allow", "deny", "warn", "forbid", "expect",
    "cfg", "doc", "deprecated", "must_use",
    "inline", "cold", "repr", "unsafe",
    "no_mangle", "export_name", "link_name", "link", "link_section", "used",
    "test", "ignore", "should_panic",
    "path", "non_exhaustive", "target_feature",
    "crate_name", "crate_type", "no_main", "no_std", "feature",
    "recursion_limit", "windows_subsystem",
}


def analyze_rust(path: str, content: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    tokens, gaps = _tokenize(path, content)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    def add(rule: str, severity: str, line: int) -> None:
        key = (rule, line)
        if key in seen:
            return
        seen.add(key)
        findings.append(finding(rule, severity, path, line))

    for index, token in enumerate(tokens):
        nxt = tokens[index + 1] if index + 1 < len(tokens) else None
        if token.in_attribute and token.kind == "ident" and token.text in _SYMBOL_ATTRS:
            add("RUST_FFI_SYMBOL", "review", token.line)
        if token.in_attribute and token.kind == "ident" and token.text == "unsafe" and nxt and nxt.text == "(":
            add("RUST_UNSAFE_INVENTORY", "review", token.line)
        if token.kind == "symbol" and token.text == "*" and not token.in_attribute:
            if nxt and nxt.kind == "ident" and nxt.text in {"const", "mut"}:
                add("RUST_RAW_POINTER", "review", token.line)
            continue
        if token.in_attribute or token.kind != "ident":
            continue
        if token.text == "unsafe":
            if nxt and (nxt.text in _UNSAFE_FOLLOW or nxt.text == "{"):
                add("RUST_UNSAFE_INVENTORY", "review", token.line)
            else:
                gaps.append({"path": path, "reason": "rust_heuristic_unclassified_unsafe"})
        elif token.text == "extern":
            if nxt and nxt.kind == "string" and nxt.text in {"C", "system"}:
                add("RUST_FFI_BOUNDARY", "review", token.line)
            elif nxt and nxt.text == "{":
                add("RUST_FFI_BOUNDARY", "review", token.line)
            elif nxt and nxt.text == "fn":
                add("RUST_FFI_BOUNDARY", "review", token.line)
            elif nxt and nxt.text == "crate":
                continue
            elif nxt is None:
                gaps.append({"path": path, "reason": "rust_heuristic_unclassified_extern"})
        elif token.text == "static" and nxt and nxt.text == "mut":
            add("RUST_STATIC_MUT", "medium", token.line)
        elif token.text == "include" and nxt and nxt.text == "!":
            row = {"path": path, "reason": "rust_macro_not_expanded"}
            if row not in gaps:
                gaps.append(row)
        if _risky_call(tokens, index):
            add("RUST_FFI_RISKY_CALL", "medium", token.line)
    _record_unresolved(path, tokens, gaps)
    findings.sort(key=lambda item: (item["line"], item["rule"]))
    gaps.sort(key=lambda item: (item["path"], item["reason"]))
    return findings, gaps


def _record_unresolved(path: str, tokens: list[_Token], gaps: list[dict[str, str]]) -> None:
    """Cfg, macros, and paths are not resolved. Record that limit instead of a clean parse."""
    seen = {(item["path"], item["reason"]) for item in gaps}

    def add(reason: str) -> None:
        key = (path, reason)
        if key in seen:
            return
        seen.add(key)
        gaps.append({"path": path, "reason": reason})

    for index, token in enumerate(tokens):
        nxt = tokens[index + 1] if index + 1 < len(tokens) else None
        if token.kind == "ident" and token.text == "cfg":
            add("rust_cfg_unresolved")
        if getattr(token, "attribute_head", False) and token.text == "cfg_attr":
            add("rust_cfg_unresolved")
        elif getattr(token, "attribute_head", False) and token.text not in _RESOLVED_ATTRIBUTE_HEADS:
            add("rust_macro_not_expanded")
        if token.kind == "ident" and nxt is not None and nxt.text == "!":
            add("rust_macro_not_expanded")
        if token.text == "::":
            add("rust_name_resolution_unresolved")


def _risky_call(tokens: list[_Token], index: int) -> bool:
    token = tokens[index]
    if token.kind != "ident":
        return False
    path: list[str] = [token.text]
    cursor = index
    while cursor >= 2 and tokens[cursor - 1].text == "::" and tokens[cursor - 2].kind == "ident":
        path.insert(0, tokens[cursor - 2].text)
        cursor -= 2
    tail = tuple(path[-2:] if len(path) >= 2 else path[-1:])
    single = (path[-1],)
    if tail not in _RISKY_TAIL and single not in _RISKY_TAIL:
        return False
    nxt = tokens[index + 1] if index + 1 < len(tokens) else None
    return nxt is not None and nxt.text in {"(", "::"}


class _Token:
    def __init__(self, kind: str, text: str, line: int, in_attribute: bool) -> None:
        self.kind = kind
        self.text = text
        self.line = line
        self.in_attribute = in_attribute
        self.attribute_head = False


def _tokenize(path: str, content: str) -> tuple[list[_Token], list[dict[str, str]]]:
    tokens: list[_Token] = []
    gaps: list[dict[str, str]] = []
    chars = content
    limit = len(chars)
    index = 0
    line = 1
    attr_depth = 0

    def gap(reason: str) -> None:
        gaps.append({"path": path, "reason": reason})

    while index < limit:
        ch = chars[index]
        if ch == "\n":
            line += 1
            index += 1
            continue
        if ch == "\r":
            if index + 1 < limit and chars[index + 1] == "\n":
                index += 1
                continue
            line += 1
            index += 1
            continue
        if ch.isspace():
            index += 1
            continue
        if chars.startswith("//", index):
            index += 2
            while index < limit and chars[index] not in "\n\r":
                index += 1
            continue
        if chars.startswith("/*", index):
            closed = _skip_block_comment(chars, index + 2)
            if closed is None:
                gap("rust_heuristic_unclosed_comment")
                break
            line += chars.count("\n", index, closed)
            index = closed
            continue
        string = _match_string(chars, index)
        if string is not None:
            end, literal = string
            if end is None:
                gap("rust_heuristic_unclosed_string")
                break
            tokens.append(_Token("string", literal, line, attr_depth > 0))
            line += chars.count("\n", index, end)
            index = end
            continue
        if ch in {"'", "b"} and _starts_char(chars, index):
            end = _skip_char(chars, index)
            if end is None:
                gap("rust_heuristic_unclosed_string")
                break
            line += chars.count("\n", index, end)
            index = end
            continue
        if ch == "'" and index + 1 < limit and (chars[index + 1].isalpha() or chars[index + 1] == "_"):
            index += 1
            while index < limit and (chars[index].isalnum() or chars[index] == "_"):
                index += 1
            continue
        if ch == "#" and _starts_attribute(chars, index):
            end = _skip_attribute(chars, index)
            if end is None:
                gap("rust_heuristic_unclosed_attribute")
                break
            bracket = chars.find("[", index, end)
            inner, inner_gaps = _tokenize(path, chars[bracket + 1:end - 1])
            for token in inner:
                token.in_attribute = True
                token.line += line - 1
            for token in inner:
                if token.kind == "ident":
                    token.attribute_head = True
                    break
            tokens.extend(inner)
            gaps.extend(inner_gaps)
            line += chars.count("\n", index, end)
            index = end
            if inner_gaps:
                break
            continue
        if ch.isalpha() or ch == "_":
            start = index
            index += 1
            while index < limit and (chars[index].isalnum() or chars[index] == "_"):
                index += 1
            tokens.append(_Token("ident", chars[start:index], line, attr_depth > 0))
            continue
        if chars.startswith("::", index):
            tokens.append(_Token("symbol", "::", line, attr_depth > 0))
            index += 2
            continue
        tokens.append(_Token("symbol", ch, line, attr_depth > 0))
        index += 1
    return tokens, gaps


def _starts_attribute(chars: str, index: int) -> bool:
    if index + 1 >= len(chars):
        return False
    if chars[index + 1] == "[":
        return True
    return index + 2 < len(chars) and chars[index + 1] == "!" and chars[index + 2] == "["


def _skip_attribute(chars: str, index: int) -> int | None:
    cursor = index + 1
    if chars[cursor] == "!":
        cursor += 1
    depth = 0
    limit = len(chars)
    while cursor < limit:
        if chars.startswith("//", cursor):
            cursor += 2
            while cursor < limit and chars[cursor] not in "\n\r":
                cursor += 1
            continue
        if chars.startswith("/*", cursor):
            closed = _skip_block_comment(chars, cursor + 2)
            if closed is None:
                return None
            cursor = closed
            continue
        string = _match_string(chars, cursor)
        if string is not None:
            end, _literal = string
            if end is None:
                return None
            cursor = end
            continue
        ch = chars[cursor]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return cursor + 1
        cursor += 1
    return None


def _skip_block_comment(chars: str, index: int) -> int | None:
    depth = 1
    limit = len(chars)
    while index < limit:
        if chars.startswith("/*", index):
            depth += 1
            index += 2
            continue
        if chars.startswith("*/", index):
            depth -= 1
            index += 2
            if depth == 0:
                return index
            continue
        index += 1
    return None


def _match_string(chars: str, index: int) -> tuple[int | None, str] | None:
    prefix = _raw_or_string_prefix(chars, index)
    if prefix is None:
        return None
    pos, raw = prefix
    hashes = 0
    if raw:
        while index + pos + hashes < len(chars) and chars[index + pos + hashes] == "#":
            hashes += 1
        pos += hashes
    if index + pos >= len(chars) or chars[index + pos] != '"':
        return None
    cursor = index + pos + 1
    limit = len(chars)
    if raw:
        closer = '"' + ("#" * hashes)
        found = chars.find(closer, cursor)
        if found < 0:
            return None, ""
        return found + len(closer), chars[cursor:found]
    while cursor < limit:
        if chars[cursor] == "\\":
            cursor += 2
            continue
        if chars[cursor] == '"':
            return cursor + 1, chars[index + pos + 1:cursor]
        cursor += 1
    return None, ""


def _raw_or_string_prefix(chars: str, index: int) -> tuple[int, bool] | None:
    for prefix in ("br", "rb", "cr", "rc"):
        if chars.startswith(prefix, index):
            return len(prefix), True
    if chars.startswith("r", index):
        return 1, True
    if chars.startswith(("b", "c"), index):
        return 1, False
    if index < len(chars) and chars[index] == '"':
        return 0, False
    return None


def _starts_char(chars: str, index: int) -> bool:
    if chars.startswith("b'", index):
        return True
    return chars.startswith("'", index) and not (
        index + 1 < len(chars) and (chars[index + 1].isalpha() or chars[index + 1] == "_")
    )


def _skip_char(chars: str, index: int) -> int | None:
    cursor = index + 2 if chars.startswith("b'", index) else index + 1
    limit = len(chars)
    if cursor < limit and chars[cursor] == "\\":
        cursor += 2
    else:
        cursor += 1
    if cursor < limit and chars[cursor] == "'":
        return cursor + 1
    return None
