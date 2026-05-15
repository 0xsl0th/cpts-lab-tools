from pathlib import Path

from reconlab.nmap import (
    merge_scan_results,
    parse_nmap_grepable,
    parse_nmap_normal,
    parse_nmap_services,
)


def _svc(port: str, proto: str = "tcp", *, host: str = "10.10.10.5",
         hostnames: str = "-", service: str = "-", product: str = "-",
         version: str = "-") -> dict[str, str]:
    return {
        "host": host,
        "hostnames": hostnames,
        "port": port,
        "proto": proto,
        "service": service,
        "product": product,
        "version": version,
    }


FIXTURES = Path(__file__).parent / "fixtures"
XML_FIXTURE = FIXTURES / "sample_nmap.xml"
NORMAL_FIXTURE = FIXTURES / "sample_nmap.nmap"
GREPABLE_FIXTURE = FIXTURES / "sample_nmap.gnmap"


EXPECTED_OPEN_PORTS = {"22", "80", "445", "3389", "9999"}


def _ports(services: list[dict[str, str]]) -> set[str]:
    return {s["port"] for s in services}


def test_parse_nmap_services_returns_only_open_ports_from_xml() -> None:
    services = parse_nmap_services(XML_FIXTURE)
    assert _ports(services) == EXPECTED_OPEN_PORTS
    assert all(s["host"] == "10.10.10.5" for s in services)


def test_parse_nmap_normal_returns_only_open_ports() -> None:
    services = parse_nmap_normal(NORMAL_FIXTURE)
    assert _ports(services) == EXPECTED_OPEN_PORTS
    assert all(s["host"] == "10.10.10.5" for s in services)
    assert all(s["hostnames"] == "target.corp.local" for s in services)


def test_parse_nmap_normal_extracts_service_and_version() -> None:
    services = {s["port"]: s for s in parse_nmap_normal(NORMAL_FIXTURE)}

    assert services["22"]["service"] == "ssh"
    assert services["22"]["product"] == "OpenSSH"
    assert "8.9p1" in services["22"]["version"]

    assert services["80"]["service"] == "http"
    assert services["80"]["product"] == "nginx"
    assert services["80"]["version"] == "1.18.0"

    assert services["445"]["service"] == "microsoft-ds"
    assert services["445"]["product"] == "Samba smbd"
    assert services["445"]["version"] == "4.15.0"

    # No VERSION column means product/version stay placeholder.
    assert services["3389"]["service"] == "ms-wbt-server"
    assert services["3389"]["product"] == "-"
    assert services["3389"]["version"] == "-"


def test_parse_nmap_normal_ignores_nse_script_lines() -> None:
    services = parse_nmap_normal(NORMAL_FIXTURE)
    for svc in services:
        for field in svc.values():
            assert "ssh-hostkey" not in field
            assert "http-title" not in field


def test_parse_nmap_normal_handles_host_without_resolved_name(tmp_path: Path) -> None:
    sample = tmp_path / "ip_only.nmap"
    sample.write_text(
        "Nmap scan report for 10.10.10.6\n"
        "PORT     STATE SERVICE VERSION\n"
        "22/tcp   open  ssh     OpenSSH 9.0\n",
        encoding="utf-8",
    )

    services = parse_nmap_normal(sample)
    assert services == [
        {
            "host": "10.10.10.6",
            "hostnames": "-",
            "port": "22",
            "proto": "tcp",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "9.0",
        }
    ]


def test_parse_nmap_normal_supports_multiple_hosts(tmp_path: Path) -> None:
    sample = tmp_path / "multi.nmap"
    sample.write_text(
        "Nmap scan report for a.corp.local (10.10.10.5)\n"
        "22/tcp open ssh OpenSSH 9.0\n"
        "Nmap scan report for b.corp.local (10.10.10.6)\n"
        "80/tcp open http nginx 1.18.0\n",
        encoding="utf-8",
    )

    services = parse_nmap_normal(sample)
    by_port = {s["port"]: s for s in services}
    assert by_port["22"]["host"] == "10.10.10.5"
    assert by_port["22"]["hostnames"] == "a.corp.local"
    assert by_port["80"]["host"] == "10.10.10.6"
    assert by_port["80"]["hostnames"] == "b.corp.local"


def test_parse_nmap_grepable_returns_only_open_ports() -> None:
    services = parse_nmap_grepable(GREPABLE_FIXTURE)
    assert _ports(services) == EXPECTED_OPEN_PORTS
    assert all(s["host"] == "10.10.10.5" for s in services)
    assert all(s["hostnames"] == "target.corp.local" for s in services)


def test_parse_nmap_grepable_extracts_service_and_version() -> None:
    services = {s["port"]: s for s in parse_nmap_grepable(GREPABLE_FIXTURE)}

    assert services["22"]["service"] == "ssh"
    assert services["22"]["product"] == "OpenSSH"
    assert "8.9p1" in services["22"]["version"]

    assert services["80"]["service"] == "http"
    assert services["80"]["product"] == "nginx"
    assert services["80"]["version"] == "1.18.0"

    assert services["3389"]["service"] == "ms-wbt-server"
    assert services["3389"]["product"] == "-"


def test_parse_nmap_grepable_skips_status_only_lines() -> None:
    services = parse_nmap_grepable(GREPABLE_FIXTURE)
    # The fixture has one "Status: Up" host line preceding the Ports line;
    # both lines share the same host IP — we must only emit ports once.
    assert len(services) == len(EXPECTED_OPEN_PORTS)


def test_grepable_and_normal_agree_with_xml_on_open_ports() -> None:
    xml_ports = _ports(parse_nmap_services(XML_FIXTURE))
    nmap_ports = _ports(parse_nmap_normal(NORMAL_FIXTURE))
    gnmap_ports = _ports(parse_nmap_grepable(GREPABLE_FIXTURE))
    assert xml_ports == nmap_ports == gnmap_ports


def test_merge_scan_results_handles_empty_input() -> None:
    assert merge_scan_results([]) == []


def test_merge_scan_results_handles_single_scan() -> None:
    single = [_svc("80", "tcp", service="http")]
    merged = merge_scan_results([(Path("only.xml"), single)])
    assert merged == single


def test_merge_scan_results_unions_distinct_ports() -> None:
    tcp = [_svc("80", "tcp", service="http")]
    udp = [_svc("53", "udp", service="domain")]
    merged = merge_scan_results(
        [(Path("tcp.xml"), tcp), (Path("udp.xml"), udp)]
    )
    keys = {(s["port"], s["proto"]) for s in merged}
    assert keys == {("80", "tcp"), ("53", "udp")}


def test_merge_scan_results_newer_metadata_overrides_older() -> None:
    older = [_svc("445", service="microsoft-ds")]
    newer = [_svc("445", service="microsoft-ds", product="Samba", version="4.15.0")]
    merged = merge_scan_results(
        [(Path("older.xml"), older), (Path("newer.xml"), newer)]
    )
    assert len(merged) == 1
    assert merged[0]["product"] == "Samba"
    assert merged[0]["version"] == "4.15.0"


def test_merge_scan_results_placeholder_does_not_overwrite_real_data() -> None:
    older = [_svc("445", service="microsoft-ds", product="Samba", version="4.15.0")]
    newer = [_svc("445", service="microsoft-ds")]  # placeholders for product/version
    merged = merge_scan_results(
        [(Path("older.xml"), older), (Path("newer.xml"), newer)]
    )
    assert merged[0]["product"] == "Samba"
    assert merged[0]["version"] == "4.15.0"


def test_merge_scan_results_sorts_by_host_proto_port() -> None:
    scans = [
        _svc("80", "tcp"),
        _svc("3389", "tcp"),
        _svc("22", "tcp"),
        _svc("53", "udp"),
    ]
    merged = merge_scan_results([(Path("a.xml"), scans)])
    ports_in_order = [(s["port"], s["proto"]) for s in merged]
    assert ports_in_order == [
        ("22", "tcp"),
        ("80", "tcp"),
        ("3389", "tcp"),
        ("53", "udp"),
    ]
