"""Workspace status — summarize a workspace's progress and the next step to take.

Lives in its own module (rather than in `workspace.py`) because it needs both
`workspace` primitives and `findings` parsing, and `findings` already imports
from `workspace` — keeping it here avoids a circular import.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .findings import ParsedFinding, list_findings, real_findings
from .workspace import WorkspaceMetadata, find_all_scans, read_metadata

# Methodology output locations written by `workspace suggest`.
_VAULT_INDEX = ("notes", "methodology", "index.md")
_MD_FILE = ("notes", "methodology.md")

_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")


@dataclass
class WorkspaceStatus:
    path: Path
    metadata: WorkspaceMetadata
    scan_count: int
    latest_scan: Path | None
    methodology: Path | None  # vault directory or methodology.md, if generated
    methodology_stale: bool  # True when a scan is newer than the methodology
    findings: list[ParsedFinding]  # scaffold placeholder excluded
    next_step: str


def _methodology_path(workspace: Path) -> Path | None:
    """Return the methodology output (vault dir or single file) if one exists."""
    vault_index = workspace.joinpath(*_VAULT_INDEX)
    if vault_index.is_file():
        return vault_index.parent
    md_file = workspace.joinpath(*_MD_FILE)
    if md_file.is_file():
        return md_file
    return None


def _methodology_mtime(methodology: Path) -> float:
    """mtime of the methodology — index.md for a vault, the file itself for md mode."""
    if methodology.is_dir():
        return methodology.joinpath("index.md").stat().st_mtime
    return methodology.stat().st_mtime


def _next_step(
    scan_count: int,
    methodology: Path | None,
    methodology_stale: bool,
    findings: list[ParsedFinding],
) -> str:
    """Pick the single most useful next action for the current workspace state."""
    if scan_count == 0:
        return "Drop an nmap scan into scans/, then run `reconlab workspace suggest`."
    if methodology is None:
        return "Run `reconlab workspace suggest` to generate methodology from scans/."
    if methodology_stale:
        return (
            "scans/ changed since the methodology was generated — re-run "
            "`reconlab workspace suggest --force`."
        )
    if not findings:
        return (
            "Work through notes/methodology/, and record results with "
            "`reconlab finding add`."
        )
    return (
        "Keep capturing findings with `reconlab finding add`; "
        "review report.md before wrap-up."
    )


def gather_status(path: Path) -> WorkspaceStatus:
    """Inspect a workspace and summarize its progress.

    Raises FileNotFoundError (with a helpful message) when *path* is not an
    initialized workspace.
    """
    path = path.resolve()
    metadata = read_metadata(path)

    scans = find_all_scans(path / "scans")  # oldest-first
    latest_scan = scans[-1] if scans else None

    methodology = _methodology_path(path)
    methodology_stale = (
        methodology is not None
        and latest_scan is not None
        and latest_scan.stat().st_mtime > _methodology_mtime(methodology)
    )

    try:
        findings = real_findings(list_findings(path))
    except FileNotFoundError:
        # Metadata exists but report.md was removed — treat as no findings.
        findings = []

    return WorkspaceStatus(
        path=path,
        metadata=metadata,
        scan_count=len(scans),
        latest_scan=latest_scan,
        methodology=methodology,
        methodology_stale=methodology_stale,
        findings=findings,
        next_step=_next_step(len(scans), methodology, methodology_stale, findings),
    )


def severity_counts(findings: list[ParsedFinding]) -> list[tuple[str, int]]:
    """Counts per severity in Critical→Info order, with any unknowns appended."""
    counter = Counter(f.severity.strip().capitalize() or "Unknown" for f in findings)
    ordered = [(sev, counter.pop(sev)) for sev in _SEVERITY_ORDER if sev in counter]
    ordered.extend(sorted(counter.items()))  # leftover / unrecognized severities
    return ordered


def format_status(status: WorkspaceStatus) -> str:
    """Render a WorkspaceStatus as a compact terminal summary."""
    md = status.metadata
    lines = [f"Workspace: {md.name}", f"Path:      {status.path}", ""]

    def row(label: str, value: str) -> str:
        return f"  {label.ljust(13)}{value}"

    target_parts = [p for p in (md.target_ip, md.target_host, md.domain) if p]
    lines.append(row("Target", " · ".join(target_parts) or "(no target set)"))
    lines.append(row("Platform", md.platform))

    if status.scan_count == 0:
        lines.append(row("Scans", "none"))
    else:
        plural = "file" if status.scan_count == 1 else "files"
        suffix = f" (latest: {status.latest_scan.name})" if status.latest_scan else ""
        lines.append(row("Scans", f"{status.scan_count} {plural}{suffix}"))

    if status.methodology is None:
        lines.append(row("Methodology", "not generated"))
    else:
        rel = status.methodology.relative_to(status.path)
        shown = f"{rel}/" if status.methodology.is_dir() else str(rel)
        if status.methodology_stale:
            shown += "  — STALE (newer scans present)"
        lines.append(row("Methodology", shown))

    if not status.findings:
        lines.append(row("Findings", "none recorded"))
    else:
        breakdown = ", ".join(
            f"{count} {sev}" for sev, count in severity_counts(status.findings)
        )
        lines.append(
            row("Findings", f"{len(status.findings)} recorded — {breakdown}")
        )

    lines.extend(["", f"Next: {status.next_step}"])
    return "\n".join(lines)
