from reconlab.services import canonicalize


def test_canonicalize_by_name() -> None:
    assert canonicalize("microsoft-ds", "445", "tcp") == "smb"
    assert canonicalize("netbios-ssn", "139", "tcp") == "smb"
    assert canonicalize("http", "80", "tcp") == "http"
    assert canonicalize("ms-wbt-server", "3389", "tcp") == "rdp"
    assert canonicalize("wsman", "5985", "tcp") == "winrm"
    assert canonicalize("kerberos-sec", "88", "tcp") == "kerberos"


def test_canonicalize_by_port_when_name_missing() -> None:
    assert canonicalize(None, 445, "tcp") == "smb"
    assert canonicalize("", 22, "tcp") == "ssh"
    assert canonicalize("unknown", 3306, "tcp") == "mysql"


def test_canonicalize_handles_udp_services() -> None:
    assert canonicalize("snmp", 161, "udp") == "snmp"
    assert canonicalize(None, 53, "udp") == "dns"


def test_canonicalize_handles_nfs() -> None:
    assert canonicalize("nfs", 2049, "tcp") == "nfs"
    assert canonicalize(None, 2049, "tcp") == "nfs"


def test_canonicalize_name_takes_precedence_over_port() -> None:
    assert canonicalize("http", 9999, "tcp") == "http"


def test_canonicalize_returns_none_for_unmapped() -> None:
    assert canonicalize("abyss", 9999, "tcp") is None
    assert canonicalize(None, 9999, "tcp") is None


def test_canonicalize_handles_non_numeric_port() -> None:
    assert canonicalize(None, "not-a-port", "tcp") is None
    assert canonicalize(None, None, "tcp") is None


def test_canonicalize_extended_services_by_name() -> None:
    assert canonicalize("oracle-tns", 1521, "tcp") == "oracle"
    assert canonicalize("imap", 143, "tcp") == "imap-pop3"
    assert canonicalize("pop3s", 995, "tcp") == "imap-pop3"
    assert canonicalize("rsync", 873, "tcp") == "rsync"
    assert canonicalize("redis", 6379, "tcp") == "redis"
    assert canonicalize("vnc", 5900, "tcp") == "vnc"


def test_canonicalize_extended_services_by_port() -> None:
    assert canonicalize(None, 1521, "tcp") == "oracle"
    assert canonicalize(None, 110, "tcp") == "imap-pop3"
    assert canonicalize(None, 873, "tcp") == "rsync"
    assert canonicalize(None, 6379, "tcp") == "redis"
    assert canonicalize(None, 5901, "tcp") == "vnc"
