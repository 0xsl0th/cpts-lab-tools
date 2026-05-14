# cpts-lab-tools

Minimal Python CLI helpers for authorized HTB/CPTS lab work. The project focuses on lab organization, scan parsing, and reporting workflows. It does not include exploit automation and is not intended for use against real third-party systems.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Usage

### Parse nmap XML

```bash
cpts-tools parse-nmap scans/target.xml
```

Example output:

```text
Host        Names       Port  Proto  Service  Product  Version
----------  ----------  ----  -----  -------  -------  -------
10.10.10.5  target.htb  80    tcp    http     nginx    1.18.0
```

### Make an `/etc/hosts` line

```bash
cpts-tools make-hosts 10.10.10.5 target.htb www.target.htb
```

Output:

```text
10.10.10.5	target.htb www.target.htb
```

### Initialize a report folder

```bash
cpts-tools report-init target --output-dir labs
```

Creates:

```text
labs/target/
├── loot/
├── notes/
├── scans/
├── screenshots/
└── report.md
```

### Generate an Obsidian note template

```bash
cpts-tools obsidian-note target --ip 10.10.10.5 > target.md
```

### Suggest the next steps from an nmap scan

`suggest-next` turns parsed nmap results into a service-based, prioritized methodology
document. Each detected service gets a checklist, command table, expected output,
verification steps, troubleshooting matrix, and a draft report note. Lab placeholders
(`[USER]`, `[PASS]`, `[LHOST]`, `[LPORT]`) are preserved for the operator to fill in.

Supported input formats:

- `xml` — nmap XML (`-oX` or `-oA`); the most reliable parser.
- `normal` — human-readable nmap output (`.nmap` files from `-oN` or `-oA`).
- `grepable` — grepable nmap output (`.gnmap` files from `-oG` or `-oA`).
- `auto` (default) — infers from the file extension; if the path has no extension,
  it is treated as an `nmap -oA` basename and the matching sibling file is probed
  in `xml → normal → grepable` priority.

```bash
# Auto-detect: scans/target resolves to scans/target.xml if present,
# otherwise scans/target.nmap, otherwise scans/target.gnmap.
cpts-tools suggest-next \
  -i scans/target \
  --input-format auto \
  --target 10.129.x.x \
  --host target.htb \
  --domain target.htb \
  -o outputs/next.md

# Force a specific parser
cpts-tools suggest-next -i scans/target.nmap  --input-format normal   --target 10.129.x.x
cpts-tools suggest-next -i scans/target.gnmap --input-format grepable --target 10.129.x.x
cpts-tools suggest-next -i scans/target.xml   --input-format xml      --target 10.129.x.x
```

The simplest invocation derives the target IP from the scan and prints Markdown to
stdout:

```bash
cpts-tools suggest-next -i scans/target.xml
```

Excerpt of the output:

```markdown
# Methodology — 10.10.10.5

## Detected Services

| Port | Proto | Service | Product | Version |
|------|-------|---------|---------|---------|
| 445  | tcp   | microsoft-ds | Samba | 4.15.0 |
| 3389 | tcp   | ms-wbt-server | - | - |

## SMB (139/445) — Share & RPC Enumeration

### Checklist
- [ ] Fingerprint SMB dialect and signing posture.
- [ ] Attempt null-session share listing.
...
```

Supported services in this release: SMB, HTTP, HTTPS, FTP, SSH, DNS, SMTP, LDAP,
Kerberos, MSSQL, MySQL, RDP, WinRM, SNMP. Open ports without a workflow are listed
under an **Unmapped Services** section so nothing is silently dropped.

`--output-format` currently accepts only `md`; the option is scaffolded so future
releases can add `json` and `obsidian` output without breaking the CLI shape.

## Development

Run syntax checks and tests:

```bash
python -m compileall src tests
python -m pytest
```
