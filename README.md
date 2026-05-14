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

## Development

Run syntax checks and tests:

```bash
python -m compileall src tests
python -m pytest
```
