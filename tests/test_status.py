import os
from pathlib import Path

import pytest

from cpts_tools.findings import Severity, add_finding
from cpts_tools.status import format_status, gather_status, severity_counts
from cpts_tools.workspace import init_workspace


def _ws(tmp_path: Path, name: str = "target") -> Path:
    workspace = tmp_path / name
    init_workspace(
        workspace,
        name=name,
        target_ip="10.10.10.5",
        target_host="app.corp.local",
        domain="corp.local",
    )
    return workspace


def _scan(workspace: Path, name: str, mtime: float | None = None) -> Path:
    scan = workspace / "scans" / name
    scan.write_text("<nmaprun/>", encoding="utf-8")
    if mtime is not None:
        os.utime(scan, (mtime, mtime))
    return scan


def _methodology_vault(workspace: Path, mtime: float | None = None) -> Path:
    vault = workspace / "notes" / "methodology"
    vault.mkdir(parents=True, exist_ok=True)
    index = vault / "index.md"
    index.write_text("# Methodology\n", encoding="utf-8")
    if mtime is not None:
        os.utime(index, (mtime, mtime))
    return vault


def test_fresh_workspace_has_no_scans_or_methodology(tmp_path: Path) -> None:
    status = gather_status(_ws(tmp_path))
    assert status.scan_count == 0
    assert status.latest_scan is None
    assert status.methodology is None
    assert status.methodology_stale is False
    assert status.findings == []
    assert "Drop an nmap scan" in status.next_step


def test_scans_present_but_no_methodology(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    _scan(workspace, "tcp.xml")
    _scan(workspace, "udp.xml")
    status = gather_status(workspace)

    assert status.scan_count == 2
    assert status.latest_scan is not None
    assert status.methodology is None
    assert "workspace suggest" in status.next_step


def test_methodology_fresh_is_not_stale(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    _scan(workspace, "tcp.xml", mtime=1000)
    _methodology_vault(workspace, mtime=2000)
    status = gather_status(workspace)

    assert status.methodology is not None
    assert status.methodology_stale is False
    assert "finding add" in status.next_step


def test_methodology_older_than_scan_is_stale(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    _methodology_vault(workspace, mtime=1000)
    _scan(workspace, "rescan.xml", mtime=2000)
    status = gather_status(workspace)

    assert status.methodology_stale is True
    assert "--force" in status.next_step


def test_md_mode_methodology_is_detected(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    _scan(workspace, "tcp.xml", mtime=1000)
    md = workspace / "notes" / "methodology.md"
    md.write_text("# Methodology\n", encoding="utf-8")
    os.utime(md, (2000, 2000))
    status = gather_status(workspace)

    assert status.methodology is not None
    assert status.methodology.name == "methodology.md"
    assert status.methodology.is_file()
    assert status.methodology_stale is False


def test_findings_counted_and_placeholder_excluded(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    _scan(workspace, "tcp.xml", mtime=1000)
    _methodology_vault(workspace, mtime=2000)
    add_finding(
        workspace, title="SMB null session", severity=Severity.HIGH, service="smb"
    )
    add_finding(workspace, title="HTTP banner", severity=Severity.LOW, service="http")
    status = gather_status(workspace)

    # Two real findings; the scaffold placeholder is not counted.
    assert len(status.findings) == 2
    assert "review report.md" in status.next_step


def test_gather_status_raises_outside_workspace(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        gather_status(tmp_path / "not-a-workspace")


def test_severity_counts_orders_critical_first(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    add_finding(workspace, title="A", severity=Severity.LOW)
    add_finding(workspace, title="B", severity=Severity.CRITICAL)
    add_finding(workspace, title="C", severity=Severity.LOW)
    counts = severity_counts(gather_status(workspace).findings)

    assert counts == [("Critical", 1), ("Low", 2)]


def test_format_status_includes_key_lines(tmp_path: Path) -> None:
    workspace = _ws(tmp_path)
    _scan(workspace, "tcp.xml", mtime=1000)
    _methodology_vault(workspace, mtime=500)  # older than the scan -> stale
    add_finding(workspace, title="SMB null session", severity=Severity.HIGH)
    rendered = format_status(gather_status(workspace))

    assert "Workspace: target" in rendered
    assert "10.10.10.5 · app.corp.local · corp.local" in rendered
    assert "1 file (latest: tcp.xml)" in rendered
    assert "STALE" in rendered
    assert "1 recorded — 1 High" in rendered
    assert "Next:" in rendered
