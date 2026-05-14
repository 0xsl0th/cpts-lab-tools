from pathlib import Path

from typer.testing import CliRunner

from cpts_tools.cli import app


runner = CliRunner()


def test_parse_nmap_prints_open_service_summary(tmp_path: Path) -> None:
    xml_file = tmp_path / "nmap.xml"
    xml_file.write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <hostnames>
      <hostname name="target.htb" type="user"/>
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
    assert "target.htb" in result.output
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


def test_make_hosts_prints_hosts_line() -> None:
    result = runner.invoke(
        app,
        ["make-hosts", "10.10.10.5", "target.htb", "www.target.htb"],
    )

    assert result.exit_code == 0
    assert result.output == "10.10.10.5\ttarget.htb www.target.htb\n"


def test_report_init_creates_machine_structure(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["report-init", "target", "--output-dir", str(tmp_path)],
    )

    machine_dir = tmp_path / "target"
    assert result.exit_code == 0
    assert (machine_dir / "scans").is_dir()
    assert (machine_dir / "screenshots").is_dir()
    assert (machine_dir / "loot").is_dir()
    assert (machine_dir / "notes").is_dir()
    assert (machine_dir / "report.md").is_file()
    assert "# target" in (machine_dir / "report.md").read_text(encoding="utf-8")


def test_obsidian_note_generates_template() -> None:
    result = runner.invoke(app, ["obsidian-note", "target", "--ip", "10.10.10.5"])

    assert result.exit_code == 0
    assert "# target" in result.output
    assert "Target IP: 10.10.10.5" in result.output
    assert "Scope: Authorized lab target only" in result.output
    assert "nmap -sV -sC -oA scans/target 10.10.10.5" in result.output


FIXTURE_DIR = Path(__file__).parent / "fixtures"
FIXTURE_XML = FIXTURE_DIR / "sample_nmap.xml"
FIXTURE_NORMAL = FIXTURE_DIR / "sample_nmap.nmap"
FIXTURE_GREPABLE = FIXTURE_DIR / "sample_nmap.gnmap"


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
            "target.htb",
            "--domain",
            "target.htb",
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
    assert "No scan file found" in result.output


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
            "target.htb",
            "--domain",
            "target.htb",
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
    assert "requires -o" in result.output


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
    assert "already exist" in second.output
    assert "--force" in second.output


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
