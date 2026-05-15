from pathlib import Path

import pytest

from reconlab.findings import (
    Finding,
    ParsedFinding,
    Severity,
    add_finding,
    format_findings_table,
    list_findings,
    render_finding_block,
)
from reconlab.workspace import WorkspaceMetadata, init_workspace


def _workspace(tmp_path: Path, **overrides) -> Path:
    base = dict(
        target_ip="10.10.10.5",
        target_host="target.corp.local",
        domain="target.corp.local",
        platform="lab",
    )
    base.update(overrides)
    workspace = tmp_path / "target"
    init_workspace(workspace, name="target", **base)
    return workspace


def test_severity_display_capitalizes() -> None:
    assert Severity.HIGH.display == "High"
    assert Severity.INFO.display == "Info"


def test_render_finding_block_includes_required_fields() -> None:
    metadata = WorkspaceMetadata(
        name="target",
        target_ip="10.10.10.5",
        target_host="target.corp.local",
        domain="target.corp.local",
    )
    finding = Finding(
        number=1,
        title="SMB null session enabled",
        severity=Severity.HIGH,
        service="smb",
        port="445",
        evidence=["screenshots/shares.png"],
    )

    block = render_finding_block(finding, metadata)
    text = "\n".join(block)

    assert "### Finding 1 — SMB null session enabled" in text
    assert "**Severity:** High" in text
    assert "`10.10.10.5`" in text
    assert "(`target.corp.local`)" in text
    assert "`smb:445`" in text
    assert "`screenshots/shares.png`" in text
    # Workflow-seeded description (paraphrase from smb workflow).
    assert "Recommend disabling SMBv1" in text
    assert "[[notes/methodology/services/smb]]" in text


def test_render_finding_block_uses_explicit_description_over_workflow() -> None:
    metadata = WorkspaceMetadata(name="target", target_ip="10.10.10.5")
    finding = Finding(
        number=1,
        title="Custom finding",
        severity=Severity.LOW,
        service="smb",
        description="Custom description text.",
    )
    text = "\n".join(render_finding_block(finding, metadata))
    assert "**Description:** Custom description text." in text
    assert "Recommend disabling SMBv1" not in text


def test_render_finding_block_without_service_omits_methodology_link() -> None:
    metadata = WorkspaceMetadata(name="target", target_ip="10.10.10.5")
    finding = Finding(
        number=2,
        title="Generic issue",
        severity=Severity.MEDIUM,
    )
    text = "\n".join(render_finding_block(finding, metadata))
    assert "Methodology" not in text


def test_add_finding_replaces_placeholder_on_first_call(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)

    number = add_finding(
        workspace,
        title="SMB null session enabled",
        severity=Severity.HIGH,
        service="smb",
        port="445",
    )

    assert number == 1
    report = (workspace / "report.md").read_text(encoding="utf-8")
    assert "### Finding 1 — SMB null session enabled" in report
    # Placeholder gone:
    assert "### Finding 1 — _Title_" not in report
    # Sibling sections still intact:
    assert "## Evidence Index" in report
    assert "## Lessons Learned" in report


def test_add_finding_appends_after_existing(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)

    add_finding(workspace, title="First", severity=Severity.HIGH, service="smb")
    second = add_finding(
        workspace,
        title="Second",
        severity=Severity.MEDIUM,
        service="http",
    )

    assert second == 2
    report = (workspace / "report.md").read_text(encoding="utf-8")
    assert "### Finding 1 — First" in report
    assert "### Finding 2 — Second" in report
    # Order is preserved:
    assert report.index("Finding 1") < report.index("Finding 2")
    # Findings stay inside the Findings section, not bleeding into siblings.
    # Split on "\n## " to avoid matching "## " inside "### Finding".
    findings_section = report.split("## Findings\n", 1)[1].split("\n## ", 1)[0]
    assert "Finding 1" in findings_section
    assert "Finding 2" in findings_section


def test_add_finding_keeps_numbering_after_gaps(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    report_path = workspace / "report.md"

    add_finding(workspace, title="A", severity=Severity.HIGH)
    add_finding(workspace, title="B", severity=Severity.MEDIUM)

    # Manually delete Finding 1 to simulate operator editing.
    text = report_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    new_lines = []
    skipping = False
    for line in lines:
        if line == "### Finding 1 — A":
            skipping = True
            continue
        if skipping and line.startswith("### Finding"):
            skipping = False
        if skipping and line.startswith("## "):
            skipping = False
        if not skipping:
            new_lines.append(line)
    report_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    third = add_finding(workspace, title="C", severity=Severity.LOW)
    # Should pick max(remaining) + 1 = 3, not reuse 1.
    assert third == 3


def test_add_finding_with_evidence_lists_each_path(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)

    add_finding(
        workspace,
        title="With evidence",
        severity=Severity.HIGH,
        evidence=["screenshots/a.png", "loot/dump.txt"],
    )

    report = (workspace / "report.md").read_text(encoding="utf-8")
    assert "  - `screenshots/a.png`" in report
    assert "  - `loot/dump.txt`" in report


def test_add_finding_substitutes_target_placeholders(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)

    add_finding(
        workspace,
        title="Substitution test",
        severity=Severity.HIGH,
        service="smb",
    )

    report = (workspace / "report.md").read_text(encoding="utf-8")
    # The smb workflow report_note mentions [TARGET_IP]; should be substituted.
    finding_text = report.split("### Finding 1")[1].split("###")[0]
    assert "[TARGET_IP]" not in finding_text
    assert "10.10.10.5" in finding_text


def test_add_finding_errors_when_no_report(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    (workspace / "report.md").unlink()

    with pytest.raises(FileNotFoundError):
        add_finding(workspace, title="X", severity=Severity.HIGH)


def test_add_finding_errors_when_no_findings_section(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    (workspace / "report.md").write_text("# title\n\nno findings section here.\n",
                                         encoding="utf-8")

    with pytest.raises(ValueError):
        add_finding(workspace, title="X", severity=Severity.HIGH)


def test_parse_findings_extracts_severity_and_service(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    add_finding(
        workspace,
        title="SMB null session enabled",
        severity=Severity.HIGH,
        service="smb",
        port="445",
    )
    add_finding(
        workspace,
        title="HTTP banner disclosure",
        severity=Severity.LOW,
        service="http",
        port="80",
    )

    findings = list_findings(workspace)
    assert [f.number for f in findings] == [1, 2]
    assert findings[0].severity == "High"
    assert "smb:445" in findings[0].service_port
    assert findings[1].severity == "Low"


def test_list_findings_on_fresh_workspace_returns_placeholder(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    findings = list_findings(workspace)
    # Fresh scaffold has the placeholder "_Title_" finding only.
    assert len(findings) == 1
    assert "_Title_" in findings[0].title


def test_format_findings_table_handles_empty() -> None:
    assert format_findings_table([]) == "No findings recorded yet."


def test_format_findings_table_renders_columns() -> None:
    rendered = format_findings_table(
        [
            ParsedFinding(1, "First", "High", "smb:445", 0, 0),
            ParsedFinding(2, "Second", "Low", "http:80", 0, 0),
        ]
    )
    assert "#" in rendered
    assert "Severity" in rendered
    assert "First" in rendered
    assert "Second" in rendered
    assert "smb:445" in rendered
