import json
import time
from pathlib import Path

import pytest

from cpts_tools.workspace import (
    METADATA_FILENAME,
    WORKSPACE_FOLDERS,
    WorkspaceMetadata,
    find_latest_scan,
    init_workspace,
    read_metadata,
    report_scaffold,
    write_metadata,
)


def test_init_workspace_creates_folder_tree_and_metadata(tmp_path: Path) -> None:
    workspace = tmp_path / "alpha"
    metadata = init_workspace(
        workspace,
        name="alpha",
        target_ip="10.10.10.5",
        target_host="alpha.corp.local",
        domain="alpha.corp.local",
        platform="lab",
    )

    assert workspace.is_dir()
    for folder in WORKSPACE_FOLDERS:
        assert (workspace / folder).is_dir(), f"missing {folder}"
    assert (workspace / METADATA_FILENAME).is_file()
    assert (workspace / "report.md").is_file()

    assert metadata.name == "alpha"
    assert metadata.target_ip == "10.10.10.5"
    assert metadata.platform == "lab"
    assert metadata.created_at  # populated with timestamp


def test_init_workspace_writes_readable_metadata(tmp_path: Path) -> None:
    workspace = tmp_path / "beta"
    init_workspace(
        workspace,
        name="beta",
        target_ip="10.10.10.6",
        target_host="beta.corp.local",
        domain="beta.corp.local",
    )

    on_disk = json.loads((workspace / METADATA_FILENAME).read_text(encoding="utf-8"))
    assert on_disk["name"] == "beta"
    assert on_disk["target_ip"] == "10.10.10.6"

    round_tripped = read_metadata(workspace)
    assert round_tripped.target_ip == "10.10.10.6"
    assert round_tripped.target_host == "beta.corp.local"


def test_init_workspace_refuses_to_overwrite_existing(tmp_path: Path) -> None:
    workspace = tmp_path / "gamma"
    init_workspace(workspace, name="gamma", target_ip="10.10.10.7")

    with pytest.raises(FileExistsError):
        init_workspace(workspace, name="gamma", target_ip="10.10.10.99")


def test_init_workspace_force_overwrites(tmp_path: Path) -> None:
    workspace = tmp_path / "delta"
    init_workspace(workspace, name="delta", target_ip="10.10.10.8")

    init_workspace(
        workspace,
        name="delta",
        target_ip="10.10.10.99",
        force=True,
    )

    assert read_metadata(workspace).target_ip == "10.10.10.99"


def test_report_scaffold_contains_target_fields() -> None:
    metadata = WorkspaceMetadata(
        name="epsilon",
        target_ip="10.10.10.9",
        target_host="epsilon.corp.local",
        domain="epsilon.corp.local",
        platform="lab",
    )
    report = report_scaffold(metadata)

    assert "# epsilon" in report
    assert "`10.10.10.9`" in report
    assert "`epsilon.corp.local`" in report
    assert "`[LHOST]`" in report  # operator placeholder preserved
    assert "[[notes/methodology/index]]" in report


def test_report_scaffold_uses_placeholders_when_no_metadata() -> None:
    metadata = WorkspaceMetadata(name="zeta")
    report = report_scaffold(metadata)
    assert "`[TARGET_IP]`" in report
    assert "`[TARGET_HOST]`" in report
    assert "`[DOMAIN]`" in report


def test_read_metadata_errors_when_missing(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError) as exc_info:
        read_metadata(tmp_path / "missing")
    assert "workspace init" in str(exc_info.value)


def test_read_metadata_ignores_unknown_keys(tmp_path: Path) -> None:
    workspace = tmp_path / "eta"
    workspace.mkdir()
    write_metadata(workspace, WorkspaceMetadata(name="eta"))
    on_disk = json.loads((workspace / METADATA_FILENAME).read_text(encoding="utf-8"))
    on_disk["future_field"] = "ignored"
    (workspace / METADATA_FILENAME).write_text(
        json.dumps(on_disk), encoding="utf-8"
    )

    metadata = read_metadata(workspace)
    assert metadata.name == "eta"


def test_find_latest_scan_returns_none_when_empty(tmp_path: Path) -> None:
    (tmp_path / "scans").mkdir()
    assert find_latest_scan(tmp_path / "scans") is None


def test_find_latest_scan_returns_none_when_dir_missing(tmp_path: Path) -> None:
    assert find_latest_scan(tmp_path / "scans") is None


def test_find_latest_scan_picks_most_recent(tmp_path: Path) -> None:
    scans = tmp_path / "scans"
    scans.mkdir()

    older = scans / "first.xml"
    older.write_text("<nmaprun/>", encoding="utf-8")
    time.sleep(0.01)
    newer = scans / "second.nmap"
    newer.write_text("Nmap scan report for x\n", encoding="utf-8")

    assert find_latest_scan(scans) == newer


def test_find_latest_scan_ignores_non_scan_extensions(tmp_path: Path) -> None:
    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / "readme.txt").write_text("not a scan", encoding="utf-8")
    scan = scans / "real.xml"
    scan.write_text("<nmaprun/>", encoding="utf-8")
    assert find_latest_scan(scans) == scan


def test_find_all_scans_returns_empty_when_missing(tmp_path: Path) -> None:
    from cpts_tools.workspace import find_all_scans

    assert find_all_scans(tmp_path / "scans") == []


def test_find_all_scans_returns_empty_when_directory_empty(tmp_path: Path) -> None:
    from cpts_tools.workspace import find_all_scans

    (tmp_path / "scans").mkdir()
    assert find_all_scans(tmp_path / "scans") == []


def test_find_all_scans_orders_oldest_first(tmp_path: Path) -> None:
    from cpts_tools.workspace import find_all_scans

    scans = tmp_path / "scans"
    scans.mkdir()
    first = scans / "first.xml"
    first.write_text("<nmaprun/>", encoding="utf-8")
    time.sleep(0.01)
    middle = scans / "middle.nmap"
    middle.write_text("Nmap scan report for x\n", encoding="utf-8")
    time.sleep(0.01)
    last = scans / "last.gnmap"
    last.write_text("# nmap done\n", encoding="utf-8")

    assert find_all_scans(scans) == [first, middle, last]


def test_find_all_scans_excludes_non_scan_files(tmp_path: Path) -> None:
    from cpts_tools.workspace import find_all_scans

    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / "notes.txt").write_text("x", encoding="utf-8")
    (scans / "loot.tar.gz").write_text("x", encoding="utf-8")
    real = scans / "real.xml"
    real.write_text("<nmaprun/>", encoding="utf-8")
    assert find_all_scans(scans) == [real]
