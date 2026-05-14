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
