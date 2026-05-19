import json
import tarfile as _tarfile
import time
from pathlib import Path

import pytest

from reconlab.workspace import (
    METADATA_FILENAME,
    WORKSPACE_FOLDERS,
    WorkspaceMetadata,
    collect_hostname_candidates,
    create_archive,
    find_latest_scan,
    init_workspace,
    read_metadata,
    report_scaffold,
    scans_have_no_xml,
    write_metadata,
)

SCRIPTED_XML = Path(__file__).parent / "fixtures" / "sample_nmap_with_scripts.xml"


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
    from reconlab.workspace import find_all_scans

    assert find_all_scans(tmp_path / "scans") == []


def test_find_all_scans_returns_empty_when_directory_empty(tmp_path: Path) -> None:
    from reconlab.workspace import find_all_scans

    (tmp_path / "scans").mkdir()
    assert find_all_scans(tmp_path / "scans") == []


def test_find_all_scans_orders_oldest_first(tmp_path: Path) -> None:
    from reconlab.workspace import find_all_scans

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


def test_init_workspace_creates_web_folder(tmp_path: Path) -> None:
    from reconlab.workspace import init_workspace

    workspace = tmp_path / "alpha"
    init_workspace(workspace, name="alpha")
    assert (workspace / "web").is_dir()


def test_find_all_web_files_empty_when_missing(tmp_path: Path) -> None:
    from reconlab.workspace import find_all_web_files

    assert find_all_web_files(tmp_path / "web") == []


def test_find_all_web_files_filters_by_extension(tmp_path: Path) -> None:
    from reconlab.workspace import find_all_web_files

    web = tmp_path / "web"
    web.mkdir()
    (web / "note.md").write_text("ignored", encoding="utf-8")
    txt = web / "ferox.txt"
    txt.write_text("x", encoding="utf-8")
    js = web / "ferox.json"
    js.write_text("{}", encoding="utf-8")
    assert set(find_all_web_files(web)) == {txt, js}


def test_find_all_scans_excludes_non_scan_files(tmp_path: Path) -> None:
    from reconlab.workspace import find_all_scans

    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / "notes.txt").write_text("x", encoding="utf-8")
    (scans / "loot.tar.gz").write_text("x", encoding="utf-8")
    real = scans / "real.xml"
    real.write_text("<nmaprun/>", encoding="utf-8")
    assert find_all_scans(scans) == [real]


def _setup_workspace_with_scan(
    tmp_path: Path,
    *,
    target_ip: str | None = "10.10.10.5",
    target_host: str | None = None,
    domain: str | None = None,
    include_scan: bool = True,
) -> Path:
    workspace = tmp_path / "wks"
    init_workspace(
        workspace,
        name="wks",
        target_ip=target_ip,
        target_host=target_host,
        domain=domain,
    )
    if include_scan:
        (workspace / "scans" / "scripted.xml").write_text(
            SCRIPTED_XML.read_text(encoding="utf-8"), encoding="utf-8"
        )
    return workspace


def test_collect_hostname_candidates_dedupes_and_merges_sources(tmp_path: Path) -> None:
    workspace = _setup_workspace_with_scan(tmp_path)
    resolved_ip, aggregated = collect_hostname_candidates(workspace)

    assert resolved_ip == "10.10.10.5"
    hostnames = {agg.hostname: agg.sources for agg in aggregated}
    assert "app.corp.local" in hostnames
    assert set(hostnames["app.corp.local"]) == {
        "dns",
        "ssl-cert CN",
        "ssl-cert SAN",
        "smb-os-discovery FQDN",
    }
    assert "dev.app.corp.local" in hostnames
    assert "intranet.corp.local" in hostnames
    assert "other.corp.local" not in hostnames  # belongs to 10.10.10.99


def test_collect_hostname_candidates_includes_metadata_target_host(
    tmp_path: Path,
) -> None:
    workspace = _setup_workspace_with_scan(
        tmp_path,
        target_host="primary.corp.local",
        include_scan=False,
    )
    _, aggregated = collect_hostname_candidates(workspace)

    hostnames = {agg.hostname for agg in aggregated}
    assert "primary.corp.local" in hostnames


def test_collect_hostname_candidates_builds_fqdn_from_host_and_domain(
    tmp_path: Path,
) -> None:
    workspace = _setup_workspace_with_scan(
        tmp_path,
        target_host="primary",
        domain="corp.local",
        include_scan=False,
    )
    _, aggregated = collect_hostname_candidates(workspace)

    hostnames = {agg.hostname for agg in aggregated}
    assert "primary" in hostnames
    assert "primary.corp.local" in hostnames


def test_collect_hostname_candidates_target_ip_override_filters_scans(
    tmp_path: Path,
) -> None:
    workspace = _setup_workspace_with_scan(tmp_path, target_ip=None)
    resolved_ip, aggregated = collect_hostname_candidates(
        workspace, target_ip="10.10.10.99"
    )

    assert resolved_ip == "10.10.10.99"
    hostnames = {agg.hostname for agg in aggregated}
    assert "other.corp.local" in hostnames
    assert "app.corp.local" not in hostnames


def test_collect_hostname_candidates_returns_none_ip_when_unset(
    tmp_path: Path,
) -> None:
    workspace = _setup_workspace_with_scan(
        tmp_path, target_ip=None, include_scan=False
    )
    resolved_ip, aggregated = collect_hostname_candidates(workspace)
    assert resolved_ip is None
    assert aggregated == []


def test_scans_have_no_xml_false_when_scans_dir_empty(tmp_path: Path) -> None:
    workspace = _setup_workspace_with_scan(tmp_path, include_scan=False)
    assert scans_have_no_xml(workspace) is False


def test_scans_have_no_xml_false_when_xml_present(tmp_path: Path) -> None:
    workspace = _setup_workspace_with_scan(tmp_path)
    assert scans_have_no_xml(workspace) is False


def test_scans_have_no_xml_false_when_mixed(tmp_path: Path) -> None:
    workspace = _setup_workspace_with_scan(tmp_path)
    (workspace / "scans" / "extra.nmap").write_text("Nmap done", encoding="utf-8")
    assert scans_have_no_xml(workspace) is False


def test_scans_have_no_xml_true_when_only_non_xml(tmp_path: Path) -> None:
    workspace = _setup_workspace_with_scan(tmp_path, include_scan=False)
    (workspace / "scans" / "scan.nmap").write_text("Nmap done", encoding="utf-8")
    (workspace / "scans" / "scan.gnmap").write_text("# Nmap done", encoding="utf-8")
    assert scans_have_no_xml(workspace) is True


def _archive_member_names(tarball: Path) -> set[str]:
    with _tarfile.open(tarball, "r:gz") as t:
        return {m.name for m in t.getmembers()}


def test_create_archive_bundles_workspace_under_named_top_dir(tmp_path: Path) -> None:
    workspace = _setup_workspace_with_scan(tmp_path, include_scan=False)
    (workspace / "scans" / "initial.nmap").write_text("Nmap done", encoding="utf-8")
    output = tmp_path / "out.tar.gz"

    result = create_archive(workspace, output, archive_name="demo")

    assert result.output == output.resolve()
    assert result.file_count > 0
    assert output.is_file()
    names = _archive_member_names(output)
    assert "demo/.reconlab.json" in names
    assert "demo/report.md" in names
    assert "demo/scans/initial.nmap" in names


def test_create_archive_defaults_archive_name_to_workspace_dir_name(
    tmp_path: Path,
) -> None:
    workspace = _setup_workspace_with_scan(tmp_path, include_scan=False)
    output = tmp_path / "out.tar.gz"

    create_archive(workspace, output)

    names = _archive_member_names(output)
    assert any(n.startswith(f"{workspace.name}/") for n in names)


def test_create_archive_excludes_pycache_pyc_dsstore_and_caches(
    tmp_path: Path,
) -> None:
    workspace = _setup_workspace_with_scan(tmp_path, include_scan=False)
    junk_dir = workspace / "__pycache__"
    junk_dir.mkdir()
    (junk_dir / "cache.pyc").write_text("x", encoding="utf-8")
    (workspace / "scans" / "stale.pyc").write_text("x", encoding="utf-8")
    (workspace / ".DS_Store").write_text("x", encoding="utf-8")
    (workspace / ".ruff_cache").mkdir()
    (workspace / ".ruff_cache" / "x").write_text("x", encoding="utf-8")

    output = tmp_path / "out.tar.gz"
    create_archive(workspace, output, archive_name="ws")

    names = _archive_member_names(output)
    assert not any("__pycache__" in n for n in names)
    assert not any(n.endswith(".pyc") for n in names)
    assert not any(n.endswith(".DS_Store") for n in names)
    assert not any(".ruff_cache" in n for n in names)


def test_create_archive_excludes_prior_archive_tarballs(tmp_path: Path) -> None:
    workspace = _setup_workspace_with_scan(tmp_path, include_scan=False)
    # Simulate a prior `reconlab workspace archive` run that wrote the tarball
    # into the workspace itself (the CLI default when run from inside it).
    (workspace / f"{workspace.name}-archive.tar.gz").write_bytes(b"prior")
    (workspace / "loot" / "anything-archive.tar.gz").write_bytes(b"nested")
    output = tmp_path / "out.tar.gz"

    create_archive(workspace, output, archive_name="ws")

    names = _archive_member_names(output)
    assert not any(n.endswith("-archive.tar.gz") for n in names)


def test_create_archive_raises_when_path_is_not_a_workspace(tmp_path: Path) -> None:
    output = tmp_path / "out.tar.gz"
    with pytest.raises(FileNotFoundError):
        create_archive(tmp_path / "nope", output, archive_name="ws")


def test_create_archive_refuses_to_overwrite_existing_output(tmp_path: Path) -> None:
    workspace = _setup_workspace_with_scan(tmp_path, include_scan=False)
    output = tmp_path / "out.tar.gz"
    output.write_text("placeholder", encoding="utf-8")

    with pytest.raises(FileExistsError):
        create_archive(workspace, output, archive_name="ws")
