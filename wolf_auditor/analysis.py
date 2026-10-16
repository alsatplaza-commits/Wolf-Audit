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

_DYNAMIC = {"eval", "exec"}
_UNSAFE_LOADS = {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "yaml.unsafe_load"}
_SUBPROCESS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
}
_SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader"}


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for element in node.elts:
            names |= _target_names(element)
        return names
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    return set()


def _module_aliases(tree: ast.AST) -> dict[str, str]:
    """Module-level import spellings. Function-local imports are not resolved."""
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    aliases[alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.name == "*":
                    continue
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _block_bound(statements: list[ast.stmt]) -> set[str]:
    """Names assigned in this block. Nested functions keep their own bindings."""
    names: set[str] = set()
    pending: list[ast.AST] = list(statements)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.Assign):
            for target in node.targets:
                names |= _target_names(target)
        elif isinstance(node, ast.AnnAssign):
            names |= _target_names(node.target)
        elif isinstance(node, ast.AugAssign):
            names |= _target_names(node.target)
        elif isinstance(node, ast.NamedExpr):
            names |= _target_names(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            names |= _target_names(node.target)
            pending.extend(node.body)
            pending.extend(node.orelse)
        elif isinstance(node, ast.If):
            for child in ast.walk(node.test):
                if isinstance(child, ast.NamedExpr):
                    names |= _target_names(child.target)
            pending.extend(node.body)
            pending.extend(node.orelse)
        elif isinstance(node, ast.While):
            pending.extend(node.body)
            pending.extend(node.orelse)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    names |= _target_names(item.optional_vars)
            pending.extend(node.body)
        elif isinstance(node, ast.Try):
            pending.extend(node.body)
            pending.extend(node.orelse)
            pending.extend(node.finalbody)
            for handler in node.handlers:
                if handler.name:
                    names.add(handler.name)
                pending.extend(handler.body)
        elif isinstance(node, ast.Match):
            for case in node.cases:
                pending.extend(case.body)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name != "*":
                    names.add(alias.asname or alias.name.split(".")[0])
    return names


def _function_bound(node: ast.AST) -> set[str]:
    names: set[str] = set()
    args = node.args
    for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
        names.add(arg.arg)
    if args.vararg is not None:
        names.add(args.vararg.arg)
    if args.kwarg is not None:
        names.add(args.kwarg.arg)
    body = node.body if isinstance(node.body, list) else []
    names |= _block_bound(body)
    return names


def _safe_yaml_loader(node: ast.Call) -> bool:
    for keyword in node.keywords:
        if keyword.arg not in {"Loader", "loader"}:
            continue
        value = keyword.value
        if isinstance(value, ast.Attribute) and value.attr in _SAFE_YAML_LOADERS:
            return True
        if isinstance(value, ast.Name) and value.id in _SAFE_YAML_LOADERS:
            return True
    return False


def _qualified_call(func: ast.AST, aliases: dict[str, str], bound: set[str]) -> str | None:
    if isinstance(func, ast.Name):
        if func.id in _DYNAMIC:
            return func.id
        if func.id in bound:
            return None
        return aliases.get(func.id)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        base = func.value.id
        if base not in bound and base in aliases:
            return f"{aliases[base]}.{func.attr}"
        return f"{base}.{func.attr}"
    return None


def _record_python_call(findings: list[dict[str, Any]], path: str, node: ast.Call,
                        aliases: dict[str, str], bound: set[str]) -> None:
    qual = _qualified_call(node.func, aliases, bound)
    if qual in _DYNAMIC or qual in {"builtins.eval", "builtins.exec"}:
        findings.append(finding("PY_DYNAMIC_EXECUTION", "high", path, node.lineno))
    elif qual == "os.system":
        findings.append(finding("PY_OS_SYSTEM", "high", path, node.lineno))
    elif qual in _UNSAFE_LOADS:
        findings.append(finding("PY_UNSAFE_DESERIALIZATION", "high", path, node.lineno))
    elif qual == "yaml.load" and not _safe_yaml_loader(node):
        findings.append(finding("PY_YAML_LOAD_REVIEW", "review", path, node.lineno))
    elif qual in _SUBPROCESS and any(
        keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
        for keyword in node.keywords
    ):
        findings.append(finding("PY_SHELL_TRUE", "high", path, node.lineno))


def python_sast(path: str, content: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return [], [{"path": path, "reason": "python_parse_failed"}]
    aliases = _module_aliases(tree)
    findings: list[dict[str, Any]] = []

    class Walker(ast.NodeVisitor):
        def __init__(self) -> None:
            self.bound_stack = [_block_bound([
                node for node in tree.body
                if not isinstance(node, (ast.Import, ast.ImportFrom))
            ])]

        def _enter(self, names: set[str], body: list[ast.stmt]) -> None:
            self.bound_stack.append(names)
            for statement in body:
                self.visit(statement)
            self.bound_stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_function(node)

        def _visit_function(self, node: ast.AST) -> None:
            for decorator in node.decorator_list:
                self.visit(decorator)
            for default in (*node.args.defaults, *node.args.kw_defaults):
                if default is not None:
                    self.visit(default)
            self._enter(_function_bound(node), node.body)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            names: set[str] = set()
            for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                names.add(arg.arg)
            for default in (*node.args.defaults, *node.args.kw_defaults):
                if default is not None:
                    self.visit(default)
            self.bound_stack.append(names)
            self.visit(node.body)
            self.bound_stack.pop()

        def _comprehension(self, node: ast.AST) -> None:
            names: set[str] = set()
            for generator in node.generators:
                names |= _target_names(generator.target)
            self.bound_stack.append(names)
            self.generic_visit(node)
            self.bound_stack.pop()

        def visit_ListComp(self, node: ast.ListComp) -> None:
            self._comprehension(node)

        def visit_SetComp(self, node: ast.SetComp) -> None:
            self._comprehension(node)

        def visit_DictComp(self, node: ast.DictComp) -> None:
            self._comprehension(node)

        def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
            self._comprehension(node)

        def visit_Call(self, node: ast.Call) -> None:
            bound: set[str] = set()
            for names in self.bound_stack:
                bound |= names
            _record_python_call(findings, path, node, aliases, bound)
            self.generic_visit(node)

    Walker().visit(tree)
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
