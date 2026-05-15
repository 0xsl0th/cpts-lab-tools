from pathlib import Path

import pytest

from cpts_tools.findings import Severity, add_finding
from cpts_tools.report import check_report, format_report_check
from cpts_tools.workspace import init_workspace

_IMPACT_PLACEHOLDER = "_Business or technical impact._"
_REMEDIATION_PLACEHOLDER = "_Specific, actionable fix — not generic advice._"
_EXEC_PLACEHOLDER = (
    "_Fill after engagement completes — 2-3 sentence summary of overall impact._"
)


def _ws(tmp_path: Path) -> Path:
    workspace = tmp_path / "target"
    init_workspace(
        workspace,
        name="target",
        target_ip="10.10.10.5",
        target_host="app.corp.local",
        domain="corp.local",
    )
    return workspace


def _fill(workspace: Path, replacements: dict[str, str]) -> None:
    report = workspace / "report.md"
    text = report.read_text(encoding="utf-8")
    for old, new in replacements.items():
        text = text.replace(old, new)
    report.write_text(text, encoding="utf-8")


def test_fresh_workspace_reports_no_findings(tmp_path: Path) -> None:
    check = check_report(_ws(tmp_path))
    assert not check.ok
    assert check.finding_count == 0
    assert any("No findings recorded" in issue for issue in check.report_issues)


def test_finding_add_leaves_impact_and_remediation_flagged(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    add_finding(
        workspace,
        title="SMB null session enabled",
        severity=Severity.HIGH,
        service="smb",
        evidence=["screenshots/smb.png"],
    )
    check = check_report(workspace)

    assert check.finding_count == 1
    [issue] = check.finding_issues
    assert issue.number == 1
    # Description seeded from the smb workflow + evidence given, so only Impact
    # and Remediation are left for the operator.
    joined = " ".join(issue.problems)
    assert "Impact" in joined
    assert "Remediation" in joined
    assert "Evidence" not in joined
    assert "Description" not in joined


def test_finding_without_evidence_or_service_flags_those_fields(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    add_finding(workspace, title="Generic issue", severity=Severity.LOW)
    [issue] = check_report(workspace).finding_issues

    joined = " ".join(issue.problems)
    assert "Evidence" in joined
    assert "Description" in joined


def test_complete_report_passes(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    add_finding(
        workspace,
        title="SMB null session enabled",
        severity=Severity.HIGH,
        service="smb",
        evidence=["screenshots/smb.png"],
    )
    _fill(
        workspace,
        {
            _IMPACT_PLACEHOLDER: "Anonymous users can read sensitive shares.",
            _REMEDIATION_PLACEHOLDER: "Disable SMBv1 and require SMB signing.",
            _EXEC_PLACEHOLDER: "The host was compromised through an SMB null session.",
        },
    )
    check = check_report(workspace)

    assert check.ok, format_report_check(check)
    assert check.finding_count == 1
    assert check.issue_count == 0


def test_exec_summary_flagged_until_filled(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    add_finding(
        workspace,
        title="SMB null session enabled",
        severity=Severity.HIGH,
        service="smb",
        evidence=["screenshots/smb.png"],
    )
    _fill(
        workspace,
        {
            _IMPACT_PLACEHOLDER: "Shares are readable.",
            _REMEDIATION_PLACEHOLDER: "Require signing.",
        },
    )
    assert any(
        "Executive Summary" in issue for issue in check_report(workspace).report_issues
    )

    _fill(workspace, {_EXEC_PLACEHOLDER: "Compromised via SMB."})
    assert check_report(workspace).ok


def test_check_report_raises_when_no_report(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    (workspace / "report.md").unlink()
    with pytest.raises(FileNotFoundError):
        check_report(workspace)


def test_format_report_check_ok_message(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    add_finding(
        workspace,
        title="SMB null session enabled",
        severity=Severity.HIGH,
        service="smb",
        evidence=["screenshots/smb.png"],
    )
    _fill(
        workspace,
        {
            _IMPACT_PLACEHOLDER: "Readable shares.",
            _REMEDIATION_PLACEHOLDER: "Require signing.",
            _EXEC_PLACEHOLDER: "Compromised via SMB.",
        },
    )
    rendered = format_report_check(check_report(workspace))

    assert "OK" in rendered
    assert "1 finding" in rendered


def test_format_report_check_lists_issues(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    add_finding(workspace, title="Generic issue", severity=Severity.LOW)
    rendered = format_report_check(check_report(workspace))

    assert "Report check:" in rendered
    assert "Finding 1 — Generic issue" in rendered
    assert "Impact" in rendered
    assert "found" in rendered  # the "N issues found — ..." summary line
