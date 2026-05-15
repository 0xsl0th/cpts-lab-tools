"""Report completeness check — flag a workspace report.md that isn't wrap-up ready.

`workspace check` parses report.md and reports the scaffold placeholders the
operator still needs to fill in: per-finding fields (Severity, Description,
Evidence, Impact, Remediation) and the Executive Summary. Logic lives here so it
can reuse the findings parser without bloating cli.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .findings import ParsedFinding, parse_findings

# A field value still wrapped in markdown italics (_..._) is a scaffold
# placeholder the operator has not filled in yet.
_ITALIC_PLACEHOLDER_RE = re.compile(r"^_.*_$")
_FIELD_RE = re.compile(r"^- \*\*(?P<field>[^:]+):\*\*\s*(?P<value>.*)$")
_EXEC_SUMMARY_RE = re.compile(r"^## Executive Summary\s*$")
_PLACEHOLDER_TITLE = "_Title_"
_REQUIRED_FINDING_FIELDS = (
    "Severity",
    "Description",
    "Evidence",
    "Impact",
    "Remediation",
)


@dataclass
class FindingIssue:
    number: int
    title: str
    problems: list[str]


@dataclass
class ReportCheck:
    path: Path
    finding_count: int  # real findings, scaffold placeholder excluded
    finding_issues: list[FindingIssue]
    report_issues: list[str]

    @property
    def ok(self) -> bool:
        return not self.finding_issues and not self.report_issues

    @property
    def issue_count(self) -> int:
        return len(self.report_issues) + sum(
            len(fi.problems) for fi in self.finding_issues
        )


def _is_unfilled(value: str) -> bool:
    """True when a field value is empty or still a `_scaffold placeholder_`."""
    return not value or bool(_ITALIC_PLACEHOLDER_RE.match(value))


def _check_finding(lines: list[str], finding: ParsedFinding) -> list[str]:
    """Return the unfilled / missing required fields for one finding block."""
    fields: dict[str, str] = {}
    evidence_has_sublist = False
    in_evidence = False
    for line in lines[finding.block_start : finding.block_end]:
        match = _FIELD_RE.match(line)
        if match:
            name = match.group("field").strip()
            fields[name] = match.group("value").strip()
            in_evidence = name == "Evidence"
            continue
        if in_evidence and line.strip().startswith("- "):
            evidence_has_sublist = True

    problems: list[str] = []
    for name in _REQUIRED_FINDING_FIELDS:
        if name not in fields:
            problems.append(f"missing **{name}**")
            continue
        # Evidence is also "filled" by a sub-bullet list of paths.
        if name == "Evidence" and evidence_has_sublist and not fields[name]:
            continue
        if _is_unfilled(fields[name]):
            problems.append(f"**{name}** is still a scaffold placeholder")
    return problems


def _exec_summary_unfilled(lines: list[str]) -> bool:
    """True when the Executive Summary section is empty or still placeholder text."""
    for i, line in enumerate(lines):
        if not _EXEC_SUMMARY_RE.match(line):
            continue
        for body in lines[i + 1 :]:
            stripped = body.strip()
            if not stripped:
                continue
            if stripped.startswith("## "):
                return True  # section is empty
            return bool(_ITALIC_PLACEHOLDER_RE.match(stripped))
        return True  # heading is the last line in the file
    return False  # no Executive Summary section — nothing to flag


def check_report(workspace_path: Path) -> ReportCheck:
    """Inspect a workspace's report.md and report scaffold placeholders left unfilled.

    Raises FileNotFoundError (with a helpful message) when report.md is absent.
    """
    report_path = workspace_path / "report.md"
    if not report_path.is_file():
        raise FileNotFoundError(
            f"No report.md at {report_path}. Run `reconlab workspace init` first."
        )

    text = report_path.read_text(encoding="utf-8")
    lines = text.splitlines()

    parsed = parse_findings(text)
    real = [f for f in parsed if f.title.strip() != _PLACEHOLDER_TITLE]

    finding_issues: list[FindingIssue] = []
    for finding in real:
        problems = _check_finding(lines, finding)
        if problems:
            finding_issues.append(
                FindingIssue(
                    number=finding.number,
                    title=finding.title.strip(),
                    problems=problems,
                )
            )

    report_issues: list[str] = []
    if not real:
        report_issues.append(
            "No findings recorded — the Findings section still has only the "
            "scaffold placeholder."
        )
    if _exec_summary_unfilled(lines):
        report_issues.append("Executive Summary is still the scaffold placeholder.")

    return ReportCheck(
        path=report_path,
        finding_count=len(real),
        finding_issues=finding_issues,
        report_issues=report_issues,
    )


def format_report_check(check: ReportCheck) -> str:
    """Render a ReportCheck as a compact terminal summary."""
    lines = [f"Report check: {check.path}", ""]

    if check.ok:
        plural = "finding" if check.finding_count == 1 else "findings"
        lines.append(
            f"  OK — {check.finding_count} {plural}, no issues. "
            "Report looks wrap-up ready."
        )
        return "\n".join(lines)

    if check.report_issues:
        lines.append("Report:")
        lines.extend(f"  - {issue}" for issue in check.report_issues)
        lines.append("")

    if check.finding_issues:
        lines.append("Findings:")
        for fi in check.finding_issues:
            lines.append(f"  Finding {fi.number} — {fi.title}")
            lines.extend(f"    - {problem}" for problem in fi.problems)
        lines.append("")

    count = check.issue_count
    plural = "issue" if count == 1 else "issues"
    lines.append(
        f"{count} {plural} found — fill these in before handing the report over."
    )
    return "\n".join(lines)
