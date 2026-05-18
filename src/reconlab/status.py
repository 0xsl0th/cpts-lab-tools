"""Workspace status - summarize a workspace's progress and the next step to take.

Lives in its own module (rather than in `workspace.py`) because it needs both
`workspace` primitives and `findings` parsing, and `findings` already imports
from `workspace` - keeping it here avoids a circular import.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .findings import ParsedFinding, list_findings, real_findings
from .web import WebFormat, merge_web_results, parse_web_results
from .workspace import (
    WorkspaceMetadata,
    find_all_scans,
    find_all_web_files,
    read_metadata,
)

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
    web_file_count: int  # files in web/ recognized as feroxbuster/gobuster output
    web_finding_count: int  # deduplicated rows across all web/ files
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
    """mtime of the methodology - index.md for a vault, the file itself for md mode."""
    if methodology.is_dir():
        return methodology.joinpath("index.md").stat().st_mtime
    return methodology.stat().st_mtime


_NEXT_INDENT = "      "  # aligns command lines under the "Next: " prefix


def _hint(summary: str, *commands: str) -> str:
    """Render a next-step hint as a description plus indented copy-pasteable commands."""
    return summary + "".join(f"\n{_NEXT_INDENT}{cmd}" for cmd in commands)


def _next_step(
    scan_count: int,
    methodology: Path | None,
    methodology_stale: bool,
    findings: list[ParsedFinding],
    web_finding_count: int,
) -> str:
    """Pick the single most useful next action for the current workspace state.

    Returns a multi-line string: the first line summarizes the situation; any
    subsequent indented lines are concrete commands ready to copy-paste.
    """
    if scan_count == 0:
        return _hint(
            "no scans yet. Drop an nmap scan into scans/, then run:",
            "reconlab workspace suggest",
        )
    if methodology is None:
        return _hint(
            "scans/ has output but no methodology generated yet. Run:",
            "reconlab workspace suggest",
        )
    if methodology_stale:
        return _hint(
            "methodology is stale relative to scans/. Re-run:",
            "reconlab workspace suggest --force",
        )
    if not findings:
        if web_finding_count:
            return _hint(
                "web findings present and no findings recorded yet. "
                "Review them, work through methodology, then capture findings:",
                "reconlab workspace ingest-web",
                "reconlab finding add --title '...' --severity high --service <id>",
            )
        return _hint(
            "no findings recorded yet. Work through notes/methodology/ and capture findings:",
            "reconlab finding add --title '...' --severity high --service <id>",
        )
    return _hint(
        "findings in progress. Keep capturing, then review report.md before wrap-up:",
        "reconlab finding add --title '...' --severity high --service <id>",
        "reconlab workspace check",
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
        # Metadata exists but report.md was removed - treat as no findings.
        findings = []

    web_files = find_all_web_files(path / "web")
    parsed_web: list[tuple[Path, list[dict[str, str]]]] = []
    for web_file in web_files:
        try:
            rows = parse_web_results(web_file, WebFormat.AUTO)
        except (ValueError, OSError):
            continue  # unparseable file - skip silently for status
        if rows:
            parsed_web.append((web_file, rows))
    web_findings = merge_web_results(parsed_web) if parsed_web else []

    return WorkspaceStatus(
        path=path,
        metadata=metadata,
        scan_count=len(scans),
        latest_scan=latest_scan,
        methodology=methodology,
        methodology_stale=methodology_stale,
        findings=findings,
        web_file_count=len(parsed_web),
        web_finding_count=len(web_findings),
        next_step=_next_step(
            len(scans),
            methodology,
            methodology_stale,
            findings,
            len(web_findings),
        ),
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
            shown += "  - STALE (newer scans present)"
        lines.append(row("Methodology", shown))

    if status.web_file_count == 0:
        lines.append(row("Web", "none"))
    else:
        plural_files = "file" if status.web_file_count == 1 else "files"
        plural_rows = "finding" if status.web_finding_count == 1 else "findings"
        lines.append(
            row(
                "Web",
                f"{status.web_finding_count} {plural_rows} across "
                f"{status.web_file_count} {plural_files}",
            )
        )

    if not status.findings:
        lines.append(row("Findings", "none recorded"))
    else:
        breakdown = ", ".join(
            f"{count} {sev}" for sev, count in severity_counts(status.findings)
        )
        lines.append(
            row("Findings", f"{len(status.findings)} recorded - {breakdown}")
        )

    lines.extend(["", f"Next: {status.next_step}"])
    return "\n".join(lines)
