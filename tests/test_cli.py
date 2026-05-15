import json
import re
import time
from pathlib import Path

from typer.testing import CliRunner

from reconlab import __version__
from reconlab.cli import app

runner = CliRunner()

# Typer force-enables Rich colored output in some environments (notably when
# GITHUB_ACTIONS is set), which injects ANSI escape codes into CLI error
# messages. Strip them so error-string assertions match the plain text
# regardless of how Typer chose to render — keeping tests stable locally and
# in CI.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    """Return *text* with ANSI escape sequences removed."""
    return _ANSI_RE.sub("", text)


def test_version_flag_prints_version_and_exits() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "reconlab" in result.output
    assert __version__ in result.output


def test_parse_nmap_prints_open_service_summary(tmp_path: Path) -> None:
    xml_file = tmp_path / "nmap.xml"
    xml_file.write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <hostnames>
      <hostname name="target.corp.local" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["parse-nmap", str(xml_file)])

    assert result.exit_code == 0
    assert "10.10.10.5" in result.output
    assert "target.corp.local" in result.output
    assert "80" in result.output
    assert "http" in result.output
    assert "nginx" in result.output
    assert "22" not in result.output


def test_parse_nmap_handles_no_open_services(tmp_path: Path) -> None:
    xml_file = tmp_path / "nmap.xml"
    xml_file.write_text(
        """<nmaprun>
  <host>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["parse-nmap", str(xml_file)])

    assert result.exit_code == 0
    assert "No open services found." in result.output


def test_make_hosts_positional_prints_hosts_entry_and_shell_command() -> None:
    result = runner.invoke(
        app,
        ["make-hosts", "10.10.10.5", "target.corp.local", "www.target.corp.local"],
    )

    assert result.exit_code == 0
    assert "# Add this to /etc/hosts:" in result.output
    assert "10.10.10.5 target.corp.local www.target.corp.local" in result.output
    assert "# Or run:" in result.output
    assert (
        'echo "10.10.10.5 target.corp.local www.target.corp.local" | sudo tee -a /etc/hosts'
        in result.output
    )


def test_make_hosts_flag_form_works() -> None:
    result = runner.invoke(
        app,
        ["make-hosts", "--ip", "10.10.10.5", "--host", "target.corp.local"],
    )

    assert result.exit_code == 0
    assert "10.10.10.5 target.corp.local" in result.output
    assert 'echo "10.10.10.5 target.corp.local" | sudo tee -a /etc/hosts' in result.output


def test_make_hosts_flag_form_with_repeated_aliases() -> None:
    result = runner.invoke(
        app,
        [
            "make-hosts",
            "--ip",
            "10.10.10.5",
            "--host",
            "target.corp.local",
            "--aliases",
            "dev.target.corp.local",
            "--aliases",
            "DEV.target.corp.local",
        ],
    )

    assert result.exit_code == 0
    assert "10.10.10.5 target.corp.local dev.target.corp.local DEV.target.corp.local" in result.output


def test_make_hosts_flag_form_collects_trailing_positional_aliases() -> None:
    # Shell-natural syntax: a single --aliases consuming one value via flag,
    # plus trailing positional args picked up as additional hostnames.
    result = runner.invoke(
        app,
        [
            "make-hosts",
            "--ip",
            "10.10.10.5",
            "--host",
            "target.corp.local",
            "--aliases",
            "dev.target.corp.local",
            "Dev.target.corp.local",
            "DEV.target.corp.local",
        ],
    )

    assert result.exit_code == 0
    assert (
        "10.10.10.5 target.corp.local dev.target.corp.local Dev.target.corp.local DEV.target.corp.local"
        in result.output
    )


def test_make_hosts_preserves_alias_casing() -> None:
    result = runner.invoke(
        app,
        ["make-hosts", "10.10.10.5", "target.corp.local", "Dev.target.corp.local", "DEV.target.corp.local"],
    )

    assert result.exit_code == 0
    assert "Dev.target.corp.local" in result.output
    assert "DEV.target.corp.local" in result.output


def test_make_hosts_no_args_errors() -> None:
    result = runner.invoke(app, ["make-hosts"])
    assert result.exit_code != 0
    assert "IP and at least one hostname" in strip_ansi(result.output)


def test_make_hosts_only_ip_errors() -> None:
    result = runner.invoke(app, ["make-hosts", "10.10.10.5"])
    assert result.exit_code != 0
    assert "at least one hostname" in strip_ansi(result.output)


def test_make_hosts_flag_form_requires_ip() -> None:
    result = runner.invoke(app, ["make-hosts", "--host", "target.corp.local"])
    assert result.exit_code != 0
    assert "--host and --aliases require --ip" in strip_ansi(result.output)


def test_make_hosts_ip_flag_alone_errors_without_hostname() -> None:
    result = runner.invoke(app, ["make-hosts", "--ip", "10.10.10.5"])
    assert result.exit_code != 0
    assert "hostname" in strip_ansi(result.output)


FIXTURE_DIR = Path(__file__).parent / "fixtures"
FIXTURE_XML = FIXTURE_DIR / "sample_nmap.xml"
FIXTURE_NORMAL = FIXTURE_DIR / "sample_nmap.nmap"
FIXTURE_GREPABLE = FIXTURE_DIR / "sample_nmap.gnmap"
FIXTURE_FEROX_TEXT = FIXTURE_DIR / "sample_feroxbuster.txt"
FIXTURE_FEROX_JSON = FIXTURE_DIR / "sample_feroxbuster.json"
FIXTURE_GOBUSTER = FIXTURE_DIR / "sample_gobuster.txt"


def test_parse_web_feroxbuster_text() -> None:
    result = runner.invoke(app, ["parse-web", str(FIXTURE_FEROX_TEXT)])
    assert result.exit_code == 0, result.output
    assert "Status" in result.output
    assert "http://10.10.10.5/admin" in result.output
    # Redirect inlined into the URL column.
    assert "http://10.10.10.5/login -> /login/" in result.output


def test_parse_web_feroxbuster_json_auto_detected() -> None:
    result = runner.invoke(app, ["parse-web", str(FIXTURE_FEROX_JSON)])
    assert result.exit_code == 0, result.output
    assert "http://10.10.10.5/admin" in result.output
    # The fixture's scan-config and report lines must not leak through.
    assert "scan-config" not in result.output
    assert "report" not in result.output


def test_parse_web_gobuster_text() -> None:
    result = runner.invoke(app, ["parse-web", str(FIXTURE_GOBUSTER)])
    assert result.exit_code == 0, result.output
    assert "/admin" in result.output
    assert "/login -> /login/" in result.output


def test_parse_web_status_filter() -> None:
    result = runner.invoke(
        app, ["parse-web", str(FIXTURE_FEROX_TEXT), "--status", "200"]
    )
    assert result.exit_code == 0, result.output
    assert "/admin" in result.output
    assert "/api/users" in result.output
    # /login (301), /.git (403), /api/upload (405) should be filtered out.
    assert "/login" not in result.output
    assert "/.git" not in result.output


def test_parse_web_explicit_format_override() -> None:
    result = runner.invoke(
        app,
        ["parse-web", str(FIXTURE_GOBUSTER), "--input-format", "gobuster"],
    )
    assert result.exit_code == 0, result.output
    assert "/admin" in result.output


def test_suggest_next_prints_methodology_to_stdout() -> None:
    result = runner.invoke(
        app,
        [
            "suggest-next",
            "-i",
            str(FIXTURE_XML),
            "--target",
            "10.10.10.5",
            "--host",
            "target.corp.local",
            "--domain",
            "target.corp.local",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "# Methodology — 10.10.10.5" in result.output
    assert "## Detected Services" in result.output
    assert "SMB (139/445)" in result.output
    assert "RDP (3389)" in result.output
    assert "SSH (22)" in result.output
    assert "## Unmapped Services" in result.output
    assert "9999/tcp" in result.output


def test_suggest_next_writes_to_output_file(tmp_path: Path) -> None:
    out_path = tmp_path / "methodology.md"
    result = runner.invoke(
        app,
        [
            "suggest-next",
            "--input",
            str(FIXTURE_XML),
            "--input-format",
            "xml",
            "--output-format",
            "md",
            "-o",
            str(out_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert out_path.is_file()
    content = out_path.read_text(encoding="utf-8")
    assert "# Methodology — 10.10.10.5" in content
    assert f"Wrote methodology to {out_path}" in result.output


def test_suggest_next_json_output_to_stdout() -> None:
    result = runner.invoke(
        app,
        ["suggest-next", "-i", str(FIXTURE_XML), "--output-format", "json"],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["target"]["ip"] == "10.10.10.5"
    assert any(w["service_id"] == "smb" for w in data["workflows"])
    assert data["unmapped_services"]  # fixture has a port without a workflow


def test_suggest_next_json_output_to_file(tmp_path: Path) -> None:
    out_path = tmp_path / "methodology.json"
    result = runner.invoke(
        app,
        [
            "suggest-next",
            "-i",
            str(FIXTURE_XML),
            "--output-format",
            "json",
            "-o",
            str(out_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert out_path.is_file()
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["target"]["ip"] == "10.10.10.5"
    assert f"Wrote methodology JSON to {out_path}" in result.output


def test_suggest_next_defaults_target_ip_from_scan() -> None:
    result = runner.invoke(app, ["suggest-next", "-i", str(FIXTURE_XML)])

    assert result.exit_code == 0, result.output
    assert "# Methodology — 10.10.10.5" in result.output


def test_suggest_next_parses_normal_format() -> None:
    result = runner.invoke(
        app,
        [
            "suggest-next",
            "-i",
            str(FIXTURE_NORMAL),
            "--input-format",
            "normal",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "# Methodology — 10.10.10.5" in result.output
    assert "SMB (139/445)" in result.output
    assert "SSH (22)" in result.output


def test_suggest_next_parses_grepable_format() -> None:
    result = runner.invoke(
        app,
        [
            "suggest-next",
            "-i",
            str(FIXTURE_GREPABLE),
            "--input-format",
            "grepable",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "# Methodology — 10.10.10.5" in result.output
    assert "RDP (3389)" in result.output


def test_suggest_next_auto_infers_xml_from_suffix() -> None:
    result = runner.invoke(
        app,
        ["suggest-next", "-i", str(FIXTURE_XML), "--input-format", "auto"],
    )
    assert result.exit_code == 0, result.output
    assert "# Methodology — 10.10.10.5" in result.output


def test_suggest_next_auto_infers_normal_from_suffix() -> None:
    result = runner.invoke(
        app,
        ["suggest-next", "-i", str(FIXTURE_NORMAL), "--input-format", "auto"],
    )
    assert result.exit_code == 0, result.output
    assert "SMB (139/445)" in result.output


def test_suggest_next_auto_infers_grepable_from_suffix() -> None:
    result = runner.invoke(
        app,
        ["suggest-next", "-i", str(FIXTURE_GREPABLE), "--input-format", "auto"],
    )
    assert result.exit_code == 0, result.output
    assert "RDP (3389)" in result.output


def test_suggest_next_auto_probes_oa_basename_with_xml_priority(tmp_path: Path) -> None:
    (tmp_path / "scan.xml").write_text(FIXTURE_XML.read_text(), encoding="utf-8")
    (tmp_path / "scan.nmap").write_text(FIXTURE_NORMAL.read_text(), encoding="utf-8")
    (tmp_path / "scan.gnmap").write_text(FIXTURE_GREPABLE.read_text(), encoding="utf-8")

    result = runner.invoke(
        app,
        ["suggest-next", "-i", str(tmp_path / "scan")],
    )
    assert result.exit_code == 0, result.output
    assert "# Methodology — 10.10.10.5" in result.output


def test_suggest_next_auto_falls_back_to_normal_when_only_nmap_exists(
    tmp_path: Path,
) -> None:
    (tmp_path / "scan.nmap").write_text(FIXTURE_NORMAL.read_text(), encoding="utf-8")

    result = runner.invoke(
        app,
        ["suggest-next", "-i", str(tmp_path / "scan")],
    )
    assert result.exit_code == 0, result.output
    assert "SMB (139/445)" in result.output


def test_suggest_next_auto_falls_back_to_grepable_when_only_gnmap_exists(
    tmp_path: Path,
) -> None:
    (tmp_path / "scan.gnmap").write_text(FIXTURE_GREPABLE.read_text(), encoding="utf-8")

    result = runner.invoke(
        app,
        ["suggest-next", "-i", str(tmp_path / "scan")],
    )
    assert result.exit_code == 0, result.output
    assert "RDP (3389)" in result.output


def test_suggest_next_errors_when_no_scan_files_match_basename(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["suggest-next", "-i", str(tmp_path / "missing")],
    )
    assert result.exit_code != 0
    assert "No scan file found" in strip_ansi(result.output)


def test_suggest_next_obsidian_writes_vault_tree(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    result = runner.invoke(
        app,
        [
            "suggest-next",
            "-i",
            str(FIXTURE_XML),
            "--target",
            "10.10.10.5",
            "--host",
            "target.corp.local",
            "--domain",
            "target.corp.local",
            "--output-format",
            "obsidian",
            "-o",
            str(vault),
        ],
    )

    assert result.exit_code == 0, result.output
    assert (vault / "index.md").is_file()
    assert (vault / "services" / "smb.md").is_file()
    assert (vault / "services" / "http.md").is_file()
    assert (vault / "services" / "rdp.md").is_file()
    assert (vault / "services" / "ssh.md").is_file()
    assert (vault / "unmapped.md").is_file()
    assert f"Wrote Obsidian vault to {vault}" in result.output

    index = (vault / "index.md").read_text(encoding="utf-8")
    assert "[[services/smb|SMB]]" in index
    assert "[[unmapped|Unmapped Services]]" in index

    smb_note = (vault / "services" / "smb.md").read_text(encoding="utf-8")
    assert smb_note.startswith("---\n")
    assert "# SMB" in smb_note
    assert "[[services/ldap|LDAP]]" in smb_note


def test_suggest_next_obsidian_requires_output_dir() -> None:
    result = runner.invoke(
        app,
        [
            "suggest-next",
            "-i",
            str(FIXTURE_XML),
            "--output-format",
            "obsidian",
        ],
    )
    assert result.exit_code != 0
    assert "requires -o" in strip_ansi(result.output)


def test_suggest_next_obsidian_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    first = runner.invoke(
        app,
        [
            "suggest-next",
            "-i",
            str(FIXTURE_XML),
            "--output-format",
            "obsidian",
            "-o",
            str(vault),
        ],
    )
    assert first.exit_code == 0, first.output

    second = runner.invoke(
        app,
        [
            "suggest-next",
            "-i",
            str(FIXTURE_XML),
            "--output-format",
            "obsidian",
            "-o",
            str(vault),
        ],
    )
    assert second.exit_code != 0
    output = strip_ansi(second.output)
    assert "already exist" in output
    assert "--force" in output


def test_suggest_next_obsidian_force_allows_overwrite(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    runner.invoke(
        app,
        [
            "suggest-next",
            "-i",
            str(FIXTURE_XML),
            "--output-format",
            "obsidian",
            "-o",
            str(vault),
        ],
    )

    result = runner.invoke(
        app,
        [
            "suggest-next",
            "-i",
            str(FIXTURE_XML),
            "--target",
            "10.10.10.99",
            "--output-format",
            "obsidian",
            "-o",
            str(vault),
            "--force",
        ],
    )

    assert result.exit_code == 0, result.output
    index = (vault / "index.md").read_text(encoding="utf-8")
    assert "10.10.10.99" in index


def test_suggest_next_obsidian_leaves_unrelated_files_alone(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    sentinel = vault / "my-notes.md"
    sentinel.write_text("hand-written notes", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "suggest-next",
            "-i",
            str(FIXTURE_XML),
            "--output-format",
            "obsidian",
            "-o",
            str(vault),
        ],
    )

    assert result.exit_code == 0, result.output
    assert sentinel.read_text(encoding="utf-8") == "hand-written notes"


def test_workspace_init_creates_layout_and_report(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "workspace",
            "init",
            "target",
            "--ip",
            "10.10.10.5",
            "--host",
            "target.corp.local",
            "--domain",
            "target.corp.local",
            "-o",
            str(tmp_path),
        ],
    )

    workspace = tmp_path / "target"
    assert result.exit_code == 0, result.output
    assert (workspace / "scans").is_dir()
    assert (workspace / "screenshots").is_dir()
    assert (workspace / "loot").is_dir()
    assert (workspace / "notes").is_dir()
    assert (workspace / "exploits").is_dir()
    assert (workspace / "creds").is_dir()
    assert (workspace / ".reconlab.json").is_file()
    report = (workspace / "report.md").read_text(encoding="utf-8")
    assert "# target" in report
    assert "`10.10.10.5`" in report
    assert "[[notes/methodology/index]]" in report
    assert "Initialized workspace" in result.output


def test_workspace_init_refuses_existing_without_force(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "-o", str(tmp_path)],
    )
    second = runner.invoke(
        app,
        ["workspace", "init", "target", "-o", str(tmp_path)],
    )
    assert second.exit_code != 0
    assert "already initialized" in strip_ansi(second.output)


def test_workspace_suggest_generates_methodology_from_latest_scan(
    tmp_path: Path,
) -> None:
    runner.invoke(
        app,
        [
            "workspace",
            "init",
            "target",
            "--ip",
            "10.10.10.5",
            "--host",
            "target.corp.local",
            "--domain",
            "target.corp.local",
            "-o",
            str(tmp_path),
        ],
    )
    workspace = tmp_path / "target"
    (workspace / "scans" / "initial.xml").write_text(
        FIXTURE_XML.read_text(), encoding="utf-8"
    )

    result = runner.invoke(app, ["workspace", "suggest", str(workspace)])

    assert result.exit_code == 0, result.output
    vault = workspace / "notes" / "methodology"
    assert (vault / "index.md").is_file()
    assert (vault / "services" / "smb.md").is_file()
    index = (vault / "index.md").read_text(encoding="utf-8")
    assert "10.10.10.5" in index
    assert "target.corp.local" in index


def test_workspace_suggest_md_mode_writes_single_file(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"
    (workspace / "scans" / "initial.xml").write_text(
        FIXTURE_XML.read_text(), encoding="utf-8"
    )

    result = runner.invoke(
        app,
        ["workspace", "suggest", str(workspace), "--output-format", "md"],
    )

    assert result.exit_code == 0, result.output
    single = workspace / "notes" / "methodology.md"
    assert single.is_file()
    assert "# Methodology — 10.10.10.5" in single.read_text(encoding="utf-8")


def test_workspace_suggest_json_mode_writes_methodology_json(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"
    (workspace / "scans" / "initial.xml").write_text(
        FIXTURE_XML.read_text(), encoding="utf-8"
    )

    result = runner.invoke(
        app,
        ["workspace", "suggest", str(workspace), "--output-format", "json"],
    )

    assert result.exit_code == 0, result.output
    out_path = workspace / "notes" / "methodology.json"
    assert out_path.is_file()
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["target"]["ip"] == "10.10.10.5"
    assert any(w["service_id"] == "smb" for w in data["workflows"])


def test_workspace_suggest_errors_when_no_metadata(tmp_path: Path) -> None:
    result = runner.invoke(app, ["workspace", "suggest", str(tmp_path)])
    assert result.exit_code != 0
    assert "workspace init" in strip_ansi(result.output)


def test_workspace_suggest_errors_when_no_scan(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    result = runner.invoke(app, ["workspace", "suggest", str(tmp_path / "target")])
    assert result.exit_code != 0
    assert "No scan file" in strip_ansi(result.output)


def test_workspace_status_summarizes_fresh_workspace(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    result = runner.invoke(app, ["workspace", "status", str(tmp_path / "target")])

    assert result.exit_code == 0, result.output
    assert "Workspace: target" in result.output
    assert "Scans" in result.output
    assert "none" in result.output
    assert "Drop an nmap scan" in result.output


def test_workspace_status_errors_outside_workspace(tmp_path: Path) -> None:
    result = runner.invoke(app, ["workspace", "status", str(tmp_path)])
    assert result.exit_code != 0
    assert "workspace init" in strip_ansi(result.output)


def test_workspace_ingest_web_merges_files(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"
    (workspace / "web" / "ferox.txt").write_text(
        FIXTURE_FEROX_TEXT.read_text(), encoding="utf-8"
    )
    (workspace / "web" / "gobuster.txt").write_text(
        FIXTURE_GOBUSTER.read_text(), encoding="utf-8"
    )

    result = runner.invoke(app, ["workspace", "ingest-web", str(workspace)])

    assert result.exit_code == 0, result.output
    assert "Merging 2 web outputs" in result.output
    assert "http://10.10.10.5/admin" in result.output  # from ferox fixture
    assert "/admin" in result.output  # from gobuster fixture (path only)


def test_workspace_ingest_web_errors_when_empty(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    result = runner.invoke(app, ["workspace", "ingest-web", str(tmp_path / "target")])
    assert result.exit_code != 0
    assert "web-output file" in strip_ansi(result.output)


def test_workspace_ingest_web_errors_outside_workspace(tmp_path: Path) -> None:
    result = runner.invoke(app, ["workspace", "ingest-web", str(tmp_path)])
    assert result.exit_code != 0
    assert "workspace init" in strip_ansi(result.output)


def test_workspace_ingest_web_status_filter(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"
    (workspace / "web" / "ferox.txt").write_text(
        FIXTURE_FEROX_TEXT.read_text(), encoding="utf-8"
    )
    result = runner.invoke(
        app,
        ["workspace", "ingest-web", str(workspace), "--status", "200"],
    )
    assert result.exit_code == 0, result.output
    assert "/admin" in result.output
    # 301/403/405 entries from the fixture should be filtered out.
    assert "/login" not in result.output
    assert "/.git" not in result.output


def test_workspace_check_flags_incomplete_report(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"
    runner.invoke(
        app,
        [
            "finding", "add",
            "--title", "SMB null session",
            "--severity", "high",
            str(workspace),
        ],
    )

    result = runner.invoke(app, ["workspace", "check", str(workspace)])
    assert result.exit_code == 1
    assert "Report check:" in result.output
    assert "Finding 1" in result.output


def test_workspace_check_passes_complete_report(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"
    runner.invoke(
        app,
        [
            "finding", "add",
            "--title", "SMB null session",
            "--severity", "high",
            "--service", "smb",
            "--evidence", "screenshots/smb.png",
            str(workspace),
        ],
    )
    report = workspace / "report.md"
    text = (
        report.read_text(encoding="utf-8")
        .replace("_Business or technical impact._", "Anonymous share read.")
        .replace(
            "_Specific, actionable fix — not generic advice._",
            "Require SMB signing.",
        )
        .replace(
            "_Fill after engagement completes — 2-3 sentence summary of "
            "overall impact._",
            "Compromised via SMB.",
        )
    )
    report.write_text(text, encoding="utf-8")

    result = runner.invoke(app, ["workspace", "check", str(workspace)])
    assert result.exit_code == 0, result.output
    assert "OK" in result.output


def test_workspace_check_errors_outside_workspace(tmp_path: Path) -> None:
    result = runner.invoke(app, ["workspace", "check", str(tmp_path)])
    assert result.exit_code != 0
    assert "workspace init" in strip_ansi(result.output)


def test_finding_add_records_in_report(tmp_path: Path) -> None:
    runner.invoke(
        app,
        [
            "workspace",
            "init",
            "target",
            "--ip",
            "10.10.10.5",
            "--host",
            "target.corp.local",
            "-o",
            str(tmp_path),
        ],
    )
    workspace = tmp_path / "target"

    result = runner.invoke(
        app,
        [
            "finding",
            "add",
            "--title",
            "SMB null session enabled",
            "--severity",
            "high",
            "--service",
            "smb",
            "--port",
            "445",
            "--evidence",
            "screenshots/shares.png",
            str(workspace),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Recorded Finding 1" in result.output
    report = (workspace / "report.md").read_text(encoding="utf-8")
    assert "### Finding 1 — SMB null session enabled" in report
    assert "**Severity:** High" in report
    assert "`screenshots/shares.png`" in report
    assert "[[notes/methodology/services/smb]]" in report


def test_finding_add_supports_multiple_evidence_paths(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"

    result = runner.invoke(
        app,
        [
            "finding",
            "add",
            "--title",
            "Multi-evidence",
            "--severity",
            "medium",
            "--evidence",
            "screenshots/a.png",
            "--evidence",
            "screenshots/b.png",
            str(workspace),
        ],
    )

    assert result.exit_code == 0, result.output
    report = (workspace / "report.md").read_text(encoding="utf-8")
    assert "`screenshots/a.png`" in report
    assert "`screenshots/b.png`" in report


def test_finding_add_increments_numbering(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"

    runner.invoke(
        app,
        ["finding", "add", "--title", "First", "--severity", "high", str(workspace)],
    )
    second = runner.invoke(
        app,
        ["finding", "add", "--title", "Second", "--severity", "low", str(workspace)],
    )

    assert second.exit_code == 0, second.output
    assert "Recorded Finding 2" in second.output


def test_finding_add_errors_outside_workspace(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "finding",
            "add",
            "--title",
            "X",
            "--severity",
            "high",
            str(tmp_path),
        ],
    )
    assert result.exit_code != 0
    assert "workspace init" in strip_ansi(result.output)


def test_finding_add_rejects_invalid_severity(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"
    result = runner.invoke(
        app,
        [
            "finding",
            "add",
            "--title",
            "X",
            "--severity",
            "catastrophic",
            str(workspace),
        ],
    )
    assert result.exit_code != 0


def test_finding_list_shows_recorded_findings(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"
    runner.invoke(
        app,
        [
            "finding",
            "add",
            "--title",
            "SMB null session enabled",
            "--severity",
            "high",
            "--service",
            "smb",
            "--port",
            "445",
            str(workspace),
        ],
    )

    result = runner.invoke(app, ["finding", "list", str(workspace)])

    assert result.exit_code == 0, result.output
    assert "SMB null session enabled" in result.output
    assert "High" in result.output
    assert "smb:445" in result.output


def test_workflow_list_includes_known_services() -> None:
    result = runner.invoke(app, ["workflow", "list"])

    assert result.exit_code == 0, result.output
    assert "smb" in result.output
    assert "SMB" in result.output
    assert "139/tcp, 445/tcp" in result.output
    assert "kerberos" in result.output
    assert "nfs" in result.output
    # Header row present.
    assert "Priority" in result.output


def test_workflow_list_orders_by_priority() -> None:
    result = runner.invoke(app, ["workflow", "list"])

    assert result.exit_code == 0, result.output
    # SMB priority 10 comes before SSH priority 35.
    smb_index = result.output.index("smb")
    ssh_index = result.output.index("ssh ")  # trailing space to avoid matching "ssh" in another field
    assert smb_index < ssh_index


def test_workflow_show_prints_full_workflow() -> None:
    result = runner.invoke(app, ["workflow", "show", "smb"])

    assert result.exit_code == 0, result.output
    assert "SMB (139/445) — Share & RPC Enumeration" in result.output
    assert "### Checklist" in result.output
    assert "### Commands" in result.output
    assert "### Troubleshooting" in result.output


def test_workflow_show_substitutes_target_placeholders() -> None:
    result = runner.invoke(
        app,
        [
            "workflow",
            "show",
            "smb",
            "--ip",
            "10.10.10.5",
            "--host",
            "target.corp.local",
            "--domain",
            "target.corp.local",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "10.10.10.5" in result.output
    assert "[TARGET_IP]" not in result.output
    # Operator placeholders preserved.
    assert "[USER]" in result.output
    assert "[PASS]" in result.output


def test_workflow_show_without_metadata_keeps_placeholders() -> None:
    result = runner.invoke(app, ["workflow", "show", "smb"])

    assert result.exit_code == 0, result.output
    assert "[TARGET_IP]" in result.output
    # No ip provided → [TARGET_HOST] stays as placeholder where the workflow used it.


def test_workflow_show_unknown_service_errors() -> None:
    result = runner.invoke(app, ["workflow", "show", "does-not-exist"])

    assert result.exit_code != 0
    output = strip_ansi(result.output)
    assert "Unknown service workflow" in output
    # Help text lists known IDs.
    assert "smb" in output


def test_workflow_list_shows_categories() -> None:
    result = runner.invoke(app, ["workflow", "list"])

    assert result.exit_code == 0, result.output
    assert "Category" in result.output
    assert "service-enum" in result.output
    assert "post-foothold" in result.output
    assert "lateral-movement" in result.output
    # Post-foothold workflows appear.
    assert "linux-privesc" in result.output
    assert "windows-privesc" in result.output
    assert "ad-foothold" in result.output
    assert "pivoting" in result.output


def test_workflow_list_orders_service_enum_before_post_foothold() -> None:
    result = runner.invoke(app, ["workflow", "list"])

    assert result.exit_code == 0, result.output
    # service-enum category sorts before post-foothold.
    assert result.output.index("smb") < result.output.index("linux-privesc")
    assert result.output.index("linux-privesc") < result.output.index("pivoting")


def test_workflow_show_linux_privesc_without_workspace() -> None:
    result = runner.invoke(app, ["workflow", "show", "linux-privesc"])

    assert result.exit_code == 0, result.output
    assert "Linux Privilege Escalation" in result.output
    assert "### Checklist" in result.output
    assert "sudo -l" in result.output


def test_workflow_show_windows_privesc_without_workspace() -> None:
    result = runner.invoke(app, ["workflow", "show", "windows-privesc"])

    assert result.exit_code == 0, result.output
    assert "Windows Privilege Escalation" in result.output
    assert "whoami /all" in result.output


def test_workflow_show_ad_foothold_substitutes_domain() -> None:
    result = runner.invoke(
        app,
        ["workflow", "show", "ad-foothold", "--domain", "target.corp.local"],
    )

    assert result.exit_code == 0, result.output
    assert "Active Directory Foothold" in result.output
    assert "target.corp.local" in result.output
    assert "[DOMAIN]" not in result.output
    # Operator placeholders preserved.
    assert "[USER]" in result.output
    assert "[PASS]" in result.output


def test_workflow_show_pivoting_without_workspace() -> None:
    result = runner.invoke(app, ["workflow", "show", "pivoting"])

    assert result.exit_code == 0, result.output
    assert "Pivoting" in result.output
    assert "proxychains" in result.output
    assert "[LHOST]" in result.output
    assert "[LPORT]" in result.output


def test_suggest_next_includes_after_foothold_footer() -> None:
    result = runner.invoke(app, ["suggest-next", "-i", str(FIXTURE_XML)])

    assert result.exit_code == 0, result.output
    assert "## After a Foothold" in result.output
    assert "reconlab workflow show linux-privesc" in result.output
    assert "reconlab workflow show pivoting" in result.output


def test_finding_list_on_empty_report_returns_placeholder_row(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"

    result = runner.invoke(app, ["finding", "list", str(workspace)])
    assert result.exit_code == 0, result.output
    # Fresh scaffold has the placeholder row.
    assert "_Title_" in result.output


def test_workspace_suggest_latest_picks_only_most_recent_scan(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"
    older = workspace / "scans" / "old.xml"
    older.write_text(
        '<nmaprun><host><address addr="10.10.10.5" addrtype="ipv4"/>'
        '<ports></ports></host></nmaprun>',
        encoding="utf-8",
    )
    time.sleep(0.01)
    newer = workspace / "scans" / "new.xml"
    newer.write_text(FIXTURE_XML.read_text(), encoding="utf-8")

    result = runner.invoke(app, ["workspace", "suggest", str(workspace), "--latest"])

    assert result.exit_code == 0, result.output
    assert f"Using scan: {newer}" in result.output
    # Older empty scan ignored when --latest is set.
    assert str(older) not in result.output


def test_workspace_suggest_merges_all_scans_by_default(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"
    tcp = workspace / "scans" / "tcp.xml"
    tcp.write_text(
        '<nmaprun>'
        '<host><address addr="10.10.10.5" addrtype="ipv4"/>'
        '<hostnames><hostname name="target.corp.local" type="user"/></hostnames>'
        '<ports>'
        '<port protocol="tcp" portid="80">'
        '<state state="open"/><service name="http" product="nginx"/>'
        '</port>'
        '</ports></host></nmaprun>',
        encoding="utf-8",
    )
    time.sleep(0.01)
    udp = workspace / "scans" / "udp.xml"
    udp.write_text(
        '<nmaprun>'
        '<host><address addr="10.10.10.5" addrtype="ipv4"/>'
        '<ports>'
        '<port protocol="udp" portid="53">'
        '<state state="open"/><service name="domain"/>'
        '</port>'
        '</ports></host></nmaprun>',
        encoding="utf-8",
    )

    result = runner.invoke(app, ["workspace", "suggest", str(workspace)])

    assert result.exit_code == 0, result.output
    assert "Merging 2 scans" in result.output
    assert str(tcp) in result.output
    assert str(udp) in result.output

    index = (workspace / "notes" / "methodology" / "index.md").read_text(
        encoding="utf-8"
    )
    # Both ports appear in the unified detected-services table.
    assert "| 80 | tcp |" in index
    assert "| 53 | udp |" in index
    # Workflows for both http and dns are picked up (wikilinks in the MOC).
    assert "[[services/http|HTTP]]" in index
    assert "[[services/dns|DNS]]" in index
    # And each has its own per-service note in the vault.
    assert (workspace / "notes" / "methodology" / "services" / "http.md").is_file()
    assert (workspace / "notes" / "methodology" / "services" / "dns.md").is_file()


def test_workspace_suggest_single_scan_says_using_scan(tmp_path: Path) -> None:
    runner.invoke(
        app,
        ["workspace", "init", "target", "--ip", "10.10.10.5", "-o", str(tmp_path)],
    )
    workspace = tmp_path / "target"
    only = workspace / "scans" / "only.xml"
    only.write_text(FIXTURE_XML.read_text(), encoding="utf-8")

    result = runner.invoke(app, ["workspace", "suggest", str(workspace)])

    assert result.exit_code == 0, result.output
    assert f"Using scan: {only}" in result.output
    assert "Merging" not in result.output
