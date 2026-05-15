"""Findings — structured capture into a workspace's report.md."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .workflows import lookup as lookup_workflow
from .workspace import WorkspaceMetadata, read_metadata

_HEADING_RE = re.compile(r"^### Finding (\d+) — (.*)$")
_FINDINGS_SECTION_RE = re.compile(r"^## Findings\s*$")
_NEXT_SECTION_RE = re.compile(r"^## ")
_PLACEHOLDER_TITLE = "_Title_"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def display(self) -> str:
        return self.value.capitalize()


@dataclass
class Finding:
    number: int
    title: str
    severity: Severity
    service: str | None = None
    port: str | None = None
    description: str | None = None
    evidence: list[str] = field(default_factory=list)


@dataclass
class ParsedFinding:
    number: int
    title: str
    severity: str
    service_port: str
    block_start: int
    block_end: int


def _apply_placeholders(text: str, metadata: WorkspaceMetadata) -> str:
    replacements = {
        "[TARGET_IP]": metadata.target_ip or "[TARGET_IP]",
        "[TARGET_HOST]": metadata.target_host or "[TARGET_HOST]",
        "[DOMAIN]": metadata.domain or "[DOMAIN]",
    }
    for key, value in replacements.items():
        text = text.replace(key, value)
    return text


def _seed_description(
    description: str | None,
    service: str | None,
    metadata: WorkspaceMetadata,
) -> str:
    if description:
        return description
    if service:
        workflow = lookup_workflow(service)
        if workflow is not None:
            return _apply_placeholders(workflow.report_note, metadata)
    return "_Fill in the issue description._"


def render_finding_block(finding: Finding, metadata: WorkspaceMetadata) -> list[str]:
    """Render a finding as a list of markdown lines (no trailing blank)."""
    lines: list[str] = []
    lines.append(f"### Finding {finding.number} — {finding.title}")
    lines.append("")
    lines.append(f"- **Severity:** {finding.severity.display}")

    target = metadata.target_ip or "[TARGET_IP]"
    affected = f"`{target}`"
    if metadata.target_host:
        affected += f" (`{metadata.target_host}`)"
    if finding.service and finding.port:
        affected += f" — `{finding.service}:{finding.port}`"
    elif finding.service:
        affected += f" — `{finding.service}`"
    elif finding.port:
        affected += f" — port `{finding.port}`"
    lines.append(f"- **Affected:** {affected}")

    description = _seed_description(finding.description, finding.service, metadata)
    lines.append(f"- **Description:** {description}")

    if finding.evidence:
        lines.append("- **Evidence:**")
        for path in finding.evidence:
            lines.append(f"  - `{path}`")
    else:
        lines.append("- **Evidence:** _Capture under `screenshots/` and link here._")

    lines.append("- **Impact:** _Business or technical impact._")
    lines.append("- **Remediation:** _Specific, actionable fix — not generic advice._")

    if finding.service and lookup_workflow(finding.service) is not None:
        lines.append(
            f"- **Methodology:** see [[notes/methodology/services/{finding.service}]]."
        )

    return lines


def _find_section_bounds(lines: list[str]) -> tuple[int, int]:
    section_start = -1
    for i, line in enumerate(lines):
        if _FINDINGS_SECTION_RE.match(line):
            section_start = i + 1
            break
    if section_start < 0:
        return -1, -1
    section_end = len(lines)
    for i in range(section_start, len(lines)):
        if _NEXT_SECTION_RE.match(lines[i]):
            section_end = i
            break
    return section_start, section_end


def _parse_findings_in_range(
    lines: list[str], start: int, end: int
) -> list[ParsedFinding]:
    findings: list[ParsedFinding] = []
    current: ParsedFinding | None = None
    for i in range(start, end):
        match = _HEADING_RE.match(lines[i])
        if match:
            if current is not None:
                current.block_end = i
                findings.append(current)
            current = ParsedFinding(
                number=int(match.group(1)),
                title=match.group(2),
                severity="",
                service_port="",
                block_start=i,
                block_end=end,
            )
            continue
        if current is None:
            continue
        if lines[i].startswith("- **Severity:**"):
            current.severity = lines[i].split("**Severity:**", 1)[1].strip()
        elif lines[i].startswith("- **Affected:**"):
            tail = lines[i].split("—", 1)
            if len(tail) > 1:
                current.service_port = tail[1].strip().strip("`")
    if current is not None:
        # Trim trailing blank lines from the last block.
        block_end = end
        while block_end > current.block_start + 1 and lines[block_end - 1].strip() == "":
            block_end -= 1
        current.block_end = block_end
        findings.append(current)
    return findings


def parse_findings(report_text: str) -> list[ParsedFinding]:
    """Return all findings in the report's `## Findings` section."""
    lines = report_text.splitlines()
    start, end = _find_section_bounds(lines)
    if start < 0:
        return []
    return _parse_findings_in_range(lines, start, end)


def add_finding(
    workspace_path: Path,
    *,
    title: str,
    severity: Severity,
    service: str | None = None,
    port: str | None = None,
    description: str | None = None,
    evidence: list[str] | None = None,
) -> int:
    """Append (or replace placeholder) a finding in the workspace's report.md.

    Returns the assigned finding number.
    """
    metadata = read_metadata(workspace_path)
    report_path = workspace_path / "report.md"
    if not report_path.is_file():
        raise FileNotFoundError(
            f"No report.md at {report_path}. Run `cpts-tools workspace init` first."
        )

    text = report_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    section_start, section_end = _find_section_bounds(lines)
    if section_start < 0:
        raise ValueError(
            f"{report_path} has no `## Findings` section — is it a cpts-tools workspace report?"
        )

    existing = _parse_findings_in_range(lines, section_start, section_end)

    is_placeholder_only = (
        len(existing) == 1 and existing[0].title.strip() == _PLACEHOLDER_TITLE
    )

    if not existing:
        assigned_number = 1
        insertion_point = section_start
        replace_range: tuple[int, int] | None = None
    elif is_placeholder_only:
        assigned_number = 1
        insertion_point = existing[0].block_start
        replace_range = (existing[0].block_start, existing[0].block_end)
    else:
        assigned_number = max(f.number for f in existing) + 1
        insertion_point = existing[-1].block_end
        replace_range = None

    finding = Finding(
        number=assigned_number,
        title=title,
        severity=severity,
        service=service,
        port=port,
        description=description,
        evidence=list(evidence or []),
    )
    block_lines = render_finding_block(finding, metadata)

    # Ensure a single trailing blank line after the new block.
    new_block = list(block_lines)
    if not new_block or new_block[-1] != "":
        new_block.append("")

    if replace_range is not None:
        rs, re_ = replace_range
        new_lines = lines[:rs] + new_block + lines[re_:]
    else:
        # Inserting at insertion_point. Ensure separation: if the preceding
        # line is not blank, prepend a blank.
        prefix = lines[:insertion_point]
        suffix = lines[insertion_point:]
        if prefix and prefix[-1].strip() != "":
            new_block = ["", *new_block]
        new_lines = prefix + new_block + suffix

    trailing_newline = "\n" if text.endswith("\n") else ""
    report_path.write_text("\n".join(new_lines) + trailing_newline, encoding="utf-8")
    return assigned_number


def list_findings(workspace_path: Path) -> list[ParsedFinding]:
    """Return the findings currently recorded in the workspace's report.md."""
    report_path = workspace_path / "report.md"
    if not report_path.is_file():
        raise FileNotFoundError(
            f"No report.md at {report_path}. Run `cpts-tools workspace init` first."
        )
    return parse_findings(report_path.read_text(encoding="utf-8"))


def real_findings(findings: list[ParsedFinding]) -> list[ParsedFinding]:
    """Drop the scaffold placeholder finding, leaving only operator-recorded ones."""
    return [f for f in findings if f.title.strip() != _PLACEHOLDER_TITLE]


def format_findings_table(findings: list[ParsedFinding]) -> str:
    """Render a short table of findings for terminal output."""
    if not findings:
        return "No findings recorded yet."

    headers = ["#", "Severity", "Title", "Service:Port"]
    rows = [
        [
            str(f.number),
            f.severity or "-",
            f.title.strip() or "-",
            f.service_port or "-",
        ]
        for f in findings
    ]
    widths = [
        max(len(row[i]) for row in [headers, *rows]) for i in range(len(headers))
    ]

    def render_row(row: list[str]) -> str:
        return "  ".join(value.ljust(widths[i]) for i, value in enumerate(row))

    separator = "  ".join("-" * w for w in widths)
    return "\n".join([render_row(headers), separator, *(render_row(row) for row in rows)])
