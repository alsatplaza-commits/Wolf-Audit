"""Limited Python AST, GitHub workflow and Dockerfile security triage (not proof)."""
from __future__ import annotations
import ast
import re
from typing import Any

SENSITIVE = re.compile(r"\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.(?:title|body)|comment\.body|head_commit\.message)\s*\}\}", re.I)
RUN = re.compile(r"^(\s*)(?:-\s*)?run:\s*(.*)$")

def finding(rule: str, severity: str, path: str, line: int) -> dict[str, Any]:
    return {"rule": rule, "severity": severity, "path": path, "line": line,
            "evidence": "heuristic_match_redacted", "verified_exploit": False}

def python_sast(path: str, content: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return [], [{"path": path, "reason": "python_parse_failed"}]
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else None
        qual = (f"{fn.value.id}.{fn.attr}"
                if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else None)
        if name in {"eval", "exec"}:
            findings.append(finding("PY_DYNAMIC_EXECUTION", "high", path, node.lineno))
        elif qual == "os.system":
            findings.append(finding("PY_OS_SYSTEM", "high", path, node.lineno))
        elif qual in {"pickle.load", "pickle.loads", "marshal.loads", "yaml.unsafe_load"}:
            findings.append(finding("PY_UNSAFE_DESERIALIZATION", "high", path, node.lineno))
        elif qual == "yaml.load":
            findings.append(finding("PY_YAML_LOAD_REVIEW", "review", path, node.lineno))
        elif qual in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output"}:
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                   for k in node.keywords):
                findings.append(finding("PY_SHELL_TRUE", "high", path, node.lineno))
    return findings, []

def workflow_sast(path: str, content: str) -> list[dict[str, Any]]:
    findings = []
    run_indent: int | None = None
    for line_no, line in enumerate(content.splitlines(), 1):
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if not stripped or stripped.startswith("#"):
            continue
        if (
            re.match(r"^\s*pull_request_target\s*:", line)
            or re.match(r"^\s*on:\s*pull_request_target(?:\s|$)", line)
            or re.match(r"^\s*-\s*pull_request_target(?:\s|$)", line)
        ):
            findings.append(finding("ACTIONS_PRIVILEGED_PR_TRIGGER_REVIEW", "review", path, line_no))
        if re.match(r"^\s*permissions\s*:\s*write-all\b", line):
            findings.append(finding("ACTIONS_WRITE_ALL_PERMISSIONS", "high", path, line_no))
        run = RUN.match(line)
        if run:
            run_indent = indent if run.group(2).strip() in {"|", "|-", ">", ">-"} else None
            if SENSITIVE.search(run.group(2)):
                findings.append(finding("ACTIONS_EVENT_EXPRESSION_IN_RUN", "high", path, line_no))
            continue
        if run_indent is not None:
            if indent <= run_indent:
                run_indent = None
            elif SENSITIVE.search(line):
                findings.append(finding("ACTIONS_EVENT_EXPRESSION_IN_RUN", "high", path, line_no))
    return findings

def docker_sast(path: str, content: str) -> list[dict[str, Any]]:
    findings = []
    for line_no, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"(?i)^FROM\s+\S+:latest(?:\s|$)", line):
            findings.append(finding("DOCKER_MUTABLE_LATEST", "medium", path, line_no))
        if re.match(r"(?i)^USER\s+(?:root|0)(?:\s|$)", line):
            findings.append(finding("DOCKER_ROOT_USER", "review", path, line_no))
    return findings
