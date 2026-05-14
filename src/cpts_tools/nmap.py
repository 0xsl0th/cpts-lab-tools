"""Nmap scan parsing — XML, normal (.nmap), and grepable (.gnmap)."""

import re
from pathlib import Path
from xml.etree import ElementTree


def _text(value: str | None, default: str = "-") -> str:
    if value is None or value.strip() == "":
        return default
    return value.strip()


def parse_nmap_services(xml_path: Path) -> list[dict[str, str]]:
    """Return one dict per open port from an nmap XML scan file."""
    root = ElementTree.parse(xml_path).getroot()
    services: list[dict[str, str]] = []

    for host in root.findall("host"):
        address = host.find("address")
        host_ip = address.get("addr", "-") if address is not None else "-"
        hostname_nodes = host.findall("hostnames/hostname")
        hostnames = ", ".join(
            name
            for node in hostname_nodes
            if (name := node.get("name"))
        )

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            services.append(
                {
                    "host": host_ip,
                    "hostnames": hostnames or "-",
                    "port": port.get("portid", "-"),
                    "proto": port.get("protocol", "-"),
                    "service": _text(service.get("name") if service is not None else None),
                    "product": _text(service.get("product") if service is not None else None),
                    "version": _text(service.get("version") if service is not None else None),
                }
            )

    return services


_NORMAL_HOST_RE = re.compile(
    r"^Nmap scan report for "
    r"(?:(?P<name>\S+)\s+\((?P<ip_with_name>\d+\.\d+\.\d+\.\d+)\)"
    r"|(?P<ip_only>\d+\.\d+\.\d+\.\d+))\s*$"
)
_NORMAL_PORT_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<service>\S+)"
    r"(?:\s+(?P<rest>.+))?$"
)


def _split_version_info(rest: str) -> tuple[str, str]:
    """Heuristic split of an nmap free-text version field into (product, version).

    Walks tokens, treating the run starting at the first digit-led token as the
    version. Stops at a parenthetical trailer (which usually holds OS/CPE info).
    """
    text = rest.strip()
    if not text:
        return "-", "-"

    product_parts: list[str] = []
    version_parts: list[str] = []
    in_version = False
    for token in text.split():
        if token.startswith("("):
            break
        if in_version:
            version_parts.append(token)
        elif token and token[0].isdigit():
            in_version = True
            version_parts.append(token)
        else:
            product_parts.append(token)

    product = " ".join(product_parts) if product_parts else "-"
    version = " ".join(version_parts) if version_parts else "-"
    return product, version


def parse_nmap_normal(path: Path) -> list[dict[str, str]]:
    """Return one dict per open port from an nmap normal (.nmap) scan file."""
    services: list[dict[str, str]] = []
    current_host = "-"
    current_hostnames = "-"

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#") or line.startswith("|"):
            continue

        host_match = _NORMAL_HOST_RE.match(line)
        if host_match:
            ip_with_name = host_match.group("ip_with_name")
            ip_only = host_match.group("ip_only")
            if ip_with_name:
                current_host = ip_with_name
                current_hostnames = host_match.group("name")
            else:
                current_host = ip_only
                current_hostnames = "-"
            continue

        port_match = _NORMAL_PORT_RE.match(line)
        if not port_match:
            continue
        if port_match.group("state") != "open":
            continue

        product, version = _split_version_info(port_match.group("rest") or "")
        services.append(
            {
                "host": current_host,
                "hostnames": current_hostnames,
                "port": port_match.group("port"),
                "proto": port_match.group("proto"),
                "service": port_match.group("service") or "-",
                "product": product,
                "version": version,
            }
        )

    return services


_GREPABLE_HOST_RE = re.compile(
    r"^Host:\s+(?P<ip>\S+)(?:\s+\((?P<name>[^)]*)\))?\s*$"
)
_GREPABLE_PORT_RE = re.compile(
    r"(?P<port>\d+)/"
    r"(?P<state>open|filtered|closed|open\|filtered|closed\|filtered)/"
    r"(?P<proto>tcp|udp)/"
    r"(?P<owner>[^/]*)/"
    r"(?P<service>[^/]*)/"
    r"(?P<sunrpc>[^/]*)/"
    r"(?P<version>[^/]*)/"
)


def parse_nmap_grepable(path: Path) -> list[dict[str, str]]:
    """Return one dict per open port from an nmap grepable (.gnmap) scan file."""
    services: list[dict[str, str]] = []

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip("\n")
        if not line or line.startswith("#"):
            continue

        host_ip = "-"
        hostname = "-"
        ports_field: str | None = None

        for field in (segment.strip() for segment in line.split("\t")):
            if field.startswith("Host:"):
                host_match = _GREPABLE_HOST_RE.match(field)
                if host_match:
                    host_ip = host_match.group("ip")
                    hostname = (host_match.group("name") or "").strip() or "-"
            elif field.startswith("Ports:"):
                ports_field = field[len("Ports:") :].strip()

        if not ports_field:
            continue

        for entry in _GREPABLE_PORT_RE.finditer(ports_field):
            if entry.group("state") != "open":
                continue
            product, version = _split_version_info(entry.group("version") or "")
            services.append(
                {
                    "host": host_ip,
                    "hostnames": hostname,
                    "port": entry.group("port"),
                    "proto": entry.group("proto"),
                    "service": (entry.group("service") or "").strip() or "-",
                    "product": product,
                    "version": version,
                }
            )

    return services
