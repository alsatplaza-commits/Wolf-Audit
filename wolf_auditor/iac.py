"""Conservative cloud IaC signals. Regex triage, not a Terraform/YAML parser."""
from __future__ import annotations

import re
from typing import Any
from .analysis import finding

def terraform_sast(path: str, content: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line_no, line in enumerate(content.splitlines(), 1):
        cleaned = line.strip()
        if cleaned.startswith(("#", "//")):
            continue
        if re.search(r'\bcidr_blocks\s*=\s*\[[^\]]*["\x27]0\.0\.0\.0/0["\x27]', line):
            out.append(finding("IAC_OPEN_IPV4_INGRESS_REVIEW", "review", path, line_no))
        if re.search(r'\bacl\s*=\s*["\x27]public-(?:read|read-write)["\x27]', line):
            out.append(finding("IAC_PUBLIC_OBJECT_ACL", "high", path, line_no))
        if re.search(r'\b(?:publicly_accessible|associate_public_ip_address)\s*=\s*true\b', line):
            out.append(finding("IAC_PUBLIC_RESOURCE_REVIEW", "review", path, line_no))
    return out

def kubernetes_sast(path: str, content: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line_no, line in enumerate(content.splitlines(), 1):
        clean = line.strip()
        if clean.startswith("#"):
            continue
        if re.search(r'^\s*privileged\s*:\s*true(?:\s|$)', line):
            out.append(finding("K8S_PRIVILEGED_CONTAINER", "high", path, line_no))
        if re.search(r'^\s*allowPrivilegeEscalation\s*:\s*true(?:\s|$)', line):
            out.append(finding("K8S_PRIVILEGE_ESCALATION", "high", path, line_no))
        if re.search(r'^\s*hostNetwork\s*:\s*true(?:\s|$)', line):
            out.append(finding("K8S_HOST_NETWORK", "review", path, line_no))
        if re.search(r'^\s*runAsUser\s*:\s*0(?:\s|$)', line):
            out.append(finding("K8S_RUN_AS_ROOT", "review", path, line_no))
    return out

def is_kubernetes_manifest(path: str) -> bool:
    path = path.lower().replace("\\", "/")
    if not path.endswith((".yml", ".yaml")) or "/.github/workflows/" in "/" + path:
        return False
    parts = path.split("/")
    return any(p in {"k8s", "kubernetes", "manifests", "helm", "templates"} for p in parts) or (
        parts[-1] in {"deployment.yml", "deployment.yaml", "pod.yml", "pod.yaml",
                       "daemonset.yml", "daemonset.yaml", "statefulset.yml", "statefulset.yaml"}
    )
