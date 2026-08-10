#!/usr/bin/env python3
"""Ordivon Security cleanup sweep.

Detects redundancy across the repository, reports it in risk tiers, and
optionally applies SAFE-tier fixes. This is the standing "cleaner" for the
lab: it enforces AGENTS.md rule 17 (no abstraction without a consumer) and
rule 18 (extract shared helpers only after multiple real consumers appear).

Usage:
    python scripts/cleanup_sweep.py                # detect + report only
    python scripts/cleanup_sweep.py --fix          # detect + apply SAFE fixes
    python scripts/cleanup_sweep.py --json         # machine-readable report

Exit code: 0 = clean, 1 = findings exist, 2 = error.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import DefaultDict, Iterable, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG = "ordivon_security"
SRC = REPO_ROOT / "src" / PKG
SCAN_ROOTS: Sequence[str] = ("src", "tests", "research", "scripts")

# Directories that may exist locally but must never be committed.
JUNK_DIR_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".cache",
}
JUNK_GLOBS = ("*.pyc", "*.pyo", "*.egg-info")

# Quarantine is a gitignored isolation area: compiled artifacts there mean
# someone executed code inside the quarantine, which admission forbids.
QUARANTINE = REPO_ROOT / "quarantine"


@dataclass
class Finding:
    tier: str  # SAFE | CAREFUL | RISKY
    category: str
    target: str
    detail: str
    fixable: bool = False
    paths: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, str]:
        return {
            "tier": self.tier,
            "category": self.category,
            "target": self.target,
            "detail": self.detail,
        }


@dataclass
class SweepReport:
    findings: list[Finding] = field(default_factory=list)

    def add(
        self,
        tier: str,
        category: str,
        target: str,
        detail: str,
        fixable: bool = False,
        paths: list[str] | None = None,
    ) -> None:
        self.findings.append(Finding(tier, category, target, detail, fixable, paths or []))

    def by_tier(self, tier: str) -> list[Finding]:
        return [f for f in self.findings if f.tier == tier]

    @property
    def count(self) -> int:
        return len(self.findings)


def _module_map() -> dict[str, Path]:
    """Map dotted module name -> absolute path for src/ordivon_security."""
    mods: dict[str, Path] = {}
    for root, _dirs, files in os.walk(SRC):
        for f in files:
            if f.endswith(".py"):
                full = Path(root) / f
                rel = full.relative_to(SRC).with_suffix("")
                mods[".".join(rel.parts)] = full
    return mods


def _import_targets(
    tree: ast.AST, file_module: str, is_src: bool, mods: dict[str, Path]
) -> set[str]:
    """Resolve every ordivon_security.* module this file references."""
    targets: set[str] = set()
    parts = file_module.split(".")
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:  # relative import
                if not is_src:
                    continue
                base = parts[: -node.level] if node.level <= len(parts) else []
                target = ".".join(base + (node.module.split(".") if node.module else []))
            elif node.module and node.module.startswith(PKG):
                target = node.module[len(PKG) + 1 :]
            else:
                continue
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(PKG):
                    target = alias.name[len(PKG) + 1 :]
                else:
                    continue
                for i in range(1, len(target.split(".")) + 1):
                    cand = ".".join(target.split(".")[:i])
                    if cand in mods:
                        targets.add(cand)
            continue
        else:
            continue
        for i in range(1, len(target.split(".")) + 1):
            cand = ".".join(target.split(".")[:i])
            if cand in mods and cand != file_module:
                targets.add(cand)
    return targets


def _scan_imports(mods: dict[str, Path]) -> tuple[DefaultDict[str, set[str]], dict[str, int]]:
    """Return (referrer -> referenced modules, module -> referrer count)."""
    refs: DefaultDict[str, set[str]] = defaultdict(set)
    for scan in SCAN_ROOTS:
        base = REPO_ROOT / scan
        if not base.is_dir():
            continue
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for f in files:
                if not f.endswith(".py"):
                    continue
                full = Path(root) / f
                try:
                    tree = ast.parse(full.read_text(encoding="utf-8"))
                except (OSError, SyntaxError):
                    continue
                if scan == "src":
                    file_mod = full.relative_to(SRC).with_suffix("")
                    file_mod = ".".join(file_mod.parts)
                    is_src = True
                else:
                    file_mod = full.relative_to(REPO_ROOT).with_suffix("")
                    file_mod = ".".join(file_mod.parts)
                    is_src = False
                for target in _import_targets(tree, file_mod, is_src, mods):
                    refs[file_mod].add(target)
    reverse: dict[str, int] = {m: 0 for m in mods}
    for referrer, targets in refs.items():
        for t in targets:
            reverse[t] += 1
    return refs, reverse


def _registered_clis() -> set[str]:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    return set(re.findall(r"ordivon_security\.(\w+):main", text))


def _has_doc_reference(module: str, mods: dict[str, Path]) -> bool:
    """Does any docs/ markdown name this module (evidence of intent)?"""
    docs_dir = REPO_ROOT / "docs"
    if not docs_dir.is_dir():
        return False
    short = module.split(".")[-1]
    for md in docs_dir.rglob("*.md"):
        try:
            if short in md.read_text(encoding="utf-8"):
                return True
        except OSError:
            continue
    return False


def _string_references(mods: dict[str, Path]) -> set[str]:
    """Modules referenced only via string (importlib.import_module, subprocess, docs).

    A module is string-referenced if the dotted name appears in any scanned
    file outside the module's own file. Self-references (a CLI embedding its
    own module name in a receipt) do not count as live consumers.
    """
    referenced: set[str] = set()
    for scan in SCAN_ROOTS:
        base = REPO_ROOT / scan
        if not base.is_dir():
            continue
        for root, _dirs, files in os.walk(base):
            if "__pycache__" in root:
                continue
            for f in files:
                if not f.endswith((".py", ".md", ".sh")):
                    continue
                full = Path(root) / f
                try:
                    text = full.read_text(encoding="utf-8")
                except OSError:
                    continue
                if scan == "src":
                    file_mod = full.relative_to(SRC).with_suffix("")
                    file_mod = ".".join(file_mod.parts)
                else:
                    file_mod = full.relative_to(REPO_ROOT).with_suffix("")
                    file_mod = ".".join(file_mod.parts)
                for module in mods:
                    # Dotted full name, e.g. ordivon_security.actors.runtime_worker
                    if f"ordivon_security.{module}" in text and module != file_mod:
                        referenced.add(module)
    return referenced


def detect(report: SweepReport) -> None:
    mods = _module_map()
    _refs, reverse = _scan_imports(mods)
    string_refs = _string_references(mods)
    registered = _registered_clis()

    # --- 1. Orphan modules (0 imports, unregistered, undocumented) -----------
    for module, count in sorted(reverse.items(), key=lambda kv: kv[1]):
        if count > 0 or module.endswith("__init__"):
            continue
        if module in registered or module in string_refs:
            continue
        lines = sum(1 for _ in mods[module].open(encoding="utf-8"))
        if module.startswith("cli_") and _has_doc_reference(module, mods):
            detail = f"{lines} 行,有 docs 背书但无代码引用(可能靠 python -m 手动跑)"
            report.add("CAREFUL", "orphan-cli-doc-backed", module, detail)
        elif module.startswith("cli_"):
            detail = f"{lines} 行,0 引用 + 未注册 + docs 未提及"
            report.add("RISKY", "orphan-cli", module, detail, fixable=True)
        else:
            detail = f"{lines} 行,0 引用 + 未注册"
            report.add("CAREFUL", "orphan-module", module, detail)

    # --- 2. Shared helpers still living inside acceptance CLIs --------------
    helper_hosts = {
        "cli_windows_kvm_s3_acceptance": "_write_receipt",
        "cli_windows_kvm_c1a_acceptance": "_git_revision",
    }
    for host, helper in helper_hosts.items():
        consumers = sorted(
            referrer
            for referrer, targets in _refs.items()
            if host in targets
        )
        if len(consumers) >= 3:
            report.add(
                "CAREFUL",
                "helper-parasite",
                f"{host}.{helper}",
                f"被 {len(consumers)} 个模块 import(AGENTS.md 18 条:应提取到公共模块): "
                + ", ".join(consumers[:8])
                + ("…" if len(consumers) > 8 else ""),
            )

    # --- 3. Acceptance-CLI cross-import web ---------------------------------
    web: dict[str, set[str]] = {}
    for referrer, targets in _refs.items():
        cli_targets = {t for t in targets if t.startswith("cli_") and t != referrer}
        if cli_targets and referrer.startswith("cli_"):
            web[referrer] = cli_targets
    if web:
        edges = sum(len(v) for v in web.values())
        report.add(
            "CAREFUL",
            "cli-cross-import-web",
            f"{len(web)} 个 CLI 互相 import",
            f"{edges} 条边:acceptance CLI 兼作共享库,应提取 helper",
        )

    # --- 4. Unregistered CLI entry points -----------------------------------
    all_clis = sorted(m for m in mods if m.startswith("cli_") and not m.endswith("__init__"))
    unregistered = [m for m in all_clis if m not in registered]
    if unregistered:
        report.add(
            "CAREFUL",
            "unregistered-cli",
            f"{len(unregistered)}/{len(all_clis)} 个 CLI 未注册进 pyproject",
            ", ".join(unregistered[:10]) + ("…" if len(unregistered) > 10 else ""),
        )

    # --- 5. Quarantine hygiene: compiled artifacts in isolation ------------
    if QUARANTINE.is_dir():
        for pyc in QUARANTINE.rglob("__pycache__"):
            report.add(
                "CAREFUL",
                "quarantine-compiled-artifact",
                str(pyc.relative_to(REPO_ROOT)),
                "隔离区出现编译产物,可能有人在隔离目录里执行过代码",
                fixable=True,
            )

    # --- 6. Junk/build artifacts on disk (not committed, but disk-worthy) ---
    junk_found: list[str] = []
    for root, dirs, files in os.walk(REPO_ROOT):
        if ".git" in root or ".venv" in root or "quarantine" in root:
            continue
        rel = Path(root)
        for d in dirs:
            if d in JUNK_DIR_NAMES:
                junk_found.append(str((rel / d).relative_to(REPO_ROOT)))
        for f in files:
            if any(f.endswith(g.lstrip("*")) for g in JUNK_GLOBS):
                junk_found.append(str((rel / f).relative_to(REPO_ROOT)))
        if rel.name == "dist" and (rel / ".gitignore").exists():
            junk_found.append(str(rel.relative_to(REPO_ROOT)))
    if junk_found:
        # Deduplicate: a __pycache__ dir and its .pyc children collapse to the dir.
        junk_dirs = {p for p in junk_found if (REPO_ROOT / p).is_dir()}
        junk_files = [p for p in junk_found if not any(
            (REPO_ROOT / p).is_relative_to(REPO_ROOT / d) for d in junk_dirs
        )]
        collapsed = sorted(junk_dirs) + sorted(junk_files)
        report.add(
            "SAFE",
            "junk-artifacts",
            f"{len(collapsed)} 个缓存/构建产物",
            ", ".join(collapsed[:10]) + ("…" if len(collapsed) > 10 else ""),
            fixable=True,
            paths=collapsed,
        )

    # --- 7. Ruff violations (respecting pyproject config) -------------------
    try:
        result = subprocess.run(
            ["ruff", "check", "--output-format", "json", "src/", "tests/"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        result = None
    if result is not None:
        try:
            violations = json.loads(result.stdout)
        except json.JSONDecodeError:
            violations = []
        by_code: dict[str, int] = defaultdict(int)
        for v in violations:
            by_code[v.get("code", "?")] += 1
        fixable = sum(1 for v in violations if v.get("fix") is not None)
        total = len(violations)
        if total:
            codes = ", ".join(f"{c}={n}" for c, n in sorted(by_code.items()))
            report.add(
                "CAREFUL",
                "ruff-violations",
                f"{total} 个违规",
                f"{codes};可自动修复 {fixable} 个",
                fixable=fixable > 0,
            )


def apply_safe_fixes(report: SweepReport, dry_run: bool = True) -> None:
    """Apply SAFE-tier fixes. Orphan-CLI archival is explicit, never automatic."""
    for f in report.by_tier("SAFE"):
        if f.category != "junk-artifacts":
            continue
        for raw in f.paths:
            path = REPO_ROOT / raw
            if not path.exists():
                continue
            label = f"删除 {raw}"
            if dry_run:
                print(f"  [dry-run] {label}")
                continue
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            print(f"  [fixed] {label}")

    # quarantine __pycache__ removal is CAREFUL-tier fixable; only with --fix.
    quarantine_pyc = [f for f in report.by_tier("CAREFUL") if f.category == "quarantine-compiled-artifact"]
    for f in quarantine_pyc:
        path = REPO_ROOT / f.target
        if not path.is_dir():
            continue
        label = f"删除隔离区编译产物 {f.target}"
        if dry_run:
            print(f"  [dry-run] {label}")
        else:
            shutil.rmtree(path)
            print(f"  [fixed] {label}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fix", action="store_true", help="apply SAFE-tier fixes")
    parser.add_argument("--json", action="store_true", help="emit machine-readable report")
    parser.add_argument("--ruff-fix", action="store_true", help="run `ruff check --fix` on src/ tests/")
    parser.add_argument(
        "--fail-on-risky",
        action="store_true",
        help="exit non-zero when RISKY-tier findings exist (CI gate)",
    )
    args = parser.parse_args(argv)

    report = SweepReport()
    detect(report)

    if args.json:
        print(json.dumps([f.as_dict() for f in report.findings], indent=1))
    else:
        tier_order = ("RISKY", "CAREFUL", "SAFE")
        for tier in tier_order:
            tier_findings = report.by_tier(tier)
            if not tier_findings:
                continue
            print(f"═══ {tier} ({len(tier_findings)}) ═══")
            for f in tier_findings:
                print(f"  [{f.category}] {f.target}")
                print(f"      {f.detail}")
            print()

    if args.fail_on_risky:
        return 1 if report.by_tier("RISKY") else 0

    if args.ruff_fix:
        print("运行 ruff check --fix …")
        subprocess.run(["ruff", "check", "--fix", "src/", "tests/"], cwd=REPO_ROOT, check=False)

    if args.fix:
        apply_safe_fixes(report, dry_run=False)
        print("SAFE 修复已应用。RISKY/CAREFUL 项请人工决定。")
    elif not args.json:
        print("提示:--fix 应用 SAFE 修复;--ruff-fix 自动修 ruff 安全项;孤儿 runner 归档始终人工。")

    return 0 if report.count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
