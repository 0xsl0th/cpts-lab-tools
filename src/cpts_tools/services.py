"""Map nmap-reported service names and well-known ports to canonical service IDs."""

_NAME_MAP: dict[str, set[str]] = {
    "smb": {"microsoft-ds", "netbios-ssn", "smb"},
    "http": {"http", "http-alt", "http-proxy"},
    "https": {"https", "ssl/http", "http/ssl"},
    "ftp": {"ftp"},
    "ssh": {"ssh"},
    "dns": {"domain", "dns"},
    "smtp": {"smtp", "submission"},
    "ldap": {"ldap", "ldaps"},
    "kerberos": {"kerberos-sec", "kerberos"},
    "mssql": {"ms-sql-s", "mssql"},
    "mysql": {"mysql"},
    "rdp": {"ms-wbt-server", "rdp"},
    "winrm": {"wsman", "winrm"},
    "snmp": {"snmp"},
    "nfs": {"nfs", "nfs_acl"},
}

_PORT_MAP: dict[str, set[tuple[int, str]]] = {
    "smb": {(139, "tcp"), (445, "tcp")},
    "http": {(80, "tcp"), (8000, "tcp"), (8008, "tcp"), (8080, "tcp")},
    "https": {(443, "tcp"), (8443, "tcp")},
    "ftp": {(21, "tcp")},
    "ssh": {(22, "tcp")},
    "dns": {(53, "tcp"), (53, "udp")},
    "smtp": {(25, "tcp"), (465, "tcp"), (587, "tcp")},
    "ldap": {(389, "tcp"), (636, "tcp")},
    "kerberos": {(88, "tcp"), (88, "udp")},
    "mssql": {(1433, "tcp")},
    "mysql": {(3306, "tcp")},
    "rdp": {(3389, "tcp")},
    "winrm": {(5985, "tcp"), (5986, "tcp")},
    "snmp": {(161, "udp")},
    "nfs": {(2049, "tcp")},
}

_NAME_INDEX: dict[str, str] = {
    name: canonical
    for canonical, names in _NAME_MAP.items()
    for name in names
}

_PORT_INDEX: dict[tuple[int, str], str] = {
    port: canonical
    for canonical, ports in _PORT_MAP.items()
    for port in ports
}


def canonicalize(
    service_name: str | None,
    port: str | int | None,
    proto: str | None,
) -> str | None:
    """Return the canonical service ID for a detected service, or None."""
    if service_name:
        name_key = service_name.strip().lower()
        if name_key in _NAME_INDEX:
            return _NAME_INDEX[name_key]

    try:
        port_int = int(port) if port is not None else None
    except (TypeError, ValueError):
        port_int = None
    if port_int is None:
        return None

    proto_key = (proto or "tcp").strip().lower()
    return _PORT_INDEX.get((port_int, proto_key))
