# cpts-lab-tools

Minimal Python CLI helpers for authorized HTB/CPTS lab work. The project focuses on lab organization, scan parsing, and reporting workflows. It does not include exploit automation and is not intended for use against real third-party systems.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Lab session walkthrough

End-to-end flow for a typical HTB/CPTS target. Replace placeholders with the
real values your lab gives you.

```bash
# 1. Scaffold a workspace with metadata baked in.
cpts-tools workspace init target \
  --ip 10.10.10.5 \
  --host target.htb \
  --domain target.htb \
  --platform htb

cd target

# 2. (Optional) Print the /etc/hosts entry and a copy-paste shell command.
#    Does NOT modify /etc/hosts — you run the printed command yourself.
cpts-tools make-hosts 10.10.10.5 target.htb

# 3. Run nmap into the workspace's scans/ folder.
sudo nmap -sV -sC -p- -oA scans/initial 10.10.10.5

# 4. Generate prioritized, service-by-service methodology as an Obsidian vault.
#    Metadata from the workspace (target IP / host / domain) is filled in
#    automatically — no need to repeat the flags.
cpts-tools workspace suggest

# 5. Open notes/methodology/index.md in Obsidian (or any Markdown editor).
#    Work through the per-service checklists; capture screenshots into
#    screenshots/, recovered files into loot/, credentials into creds/.

# 6. Update report.md with findings as you go. A scaffold is already there.
```

Layout produced by `workspace init`:

```text
target/
├── .cpts-tools.json    # target metadata (ip, host, domain, platform)
├── report.md           # engagement report scaffold with frontmatter
├── scans/              # raw nmap output (xml/nmap/gnmap)
├── screenshots/        # one set per finding
├── loot/               # recovered files (sanitized before report)
├── notes/              # working notes + generated methodology vault
├── exploits/           # adapted exploit code with attribution
└── creds/              # recovered credentials — gitignored
```

After `workspace suggest`, `notes/methodology/` contains an Obsidian-friendly
vault with one MOC (`index.md`) and one note per detected service.

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

### Make an `/etc/hosts` entry

`make-hosts` is a read-only helper. It prints the line you should add to
`/etc/hosts` plus a ready-to-paste shell command. It never modifies any file.

Positional form:

```bash
cpts-tools make-hosts 10.10.10.5 target.htb dev.target.htb Dev.target.htb DEV.target.htb
```

Output:

```text
# Add this to /etc/hosts:
10.10.10.5 target.htb dev.target.htb Dev.target.htb DEV.target.htb

# Or run:
echo "10.10.10.5 target.htb dev.target.htb Dev.target.htb DEV.target.htb" | sudo tee -a /etc/hosts
```

Flag form (equivalent output):

```bash
cpts-tools make-hosts \
  --ip 10.10.10.5 \
  --host target.htb \
  --aliases dev.target.htb Dev.target.htb DEV.target.htb
```

In the flag form, the first value after `--aliases` is consumed by the flag and
any further positional arguments are appended as additional aliases — so the
shell-natural `--aliases a b c` syntax works. Repeating the flag
(`--aliases a --aliases b`) is also supported. Hostname casing is preserved
exactly as typed.

### Manage a lab workspace

`workspace init` scaffolds a target folder with a richer report template and
persists target metadata so downstream commands inherit it.

```bash
cpts-tools workspace init target \
  --ip 10.10.10.5 \
  --host target.htb \
  --domain target.htb \
  --platform htb \
  -o ~/labs
```

`workspace suggest` finds the most recent scan file in `scans/` and generates
methodology into `notes/methodology/` (Obsidian vault by default) or
`notes/methodology.md` (with `--output-format md`):

```bash
# From inside the workspace, no flags needed.
cpts-tools workspace suggest

# Or explicitly point at a workspace.
cpts-tools workspace suggest ~/labs/target --output-format md --force
```

Re-running refuses to overwrite the previous methodology unless `--force` is
passed; unrelated files in the workspace are never touched.

### Initialize a report folder (legacy)

`report-init` is the simpler predecessor of `workspace init` — it creates the
folder tree only, without metadata or the richer report scaffold.

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

### Generate an Obsidian note template (legacy)

`obsidian-note` is a simple single-file note scaffold from before the Obsidian
vault renderer existed. For new work, prefer `workspace init` + `workspace
suggest` — the generated vault is richer and stays in sync with scan results.

```bash
cpts-tools obsidian-note target --ip 10.10.10.5 > target.md
```

### Suggest the next steps from an nmap scan

`suggest-next` is the underlying methodology generator. For the typical case
(one workspace, drop a scan into `scans/`, get a vault back) prefer
`cpts-tools workspace suggest` — it picks up the latest scan and the workspace
metadata automatically. Reach for `suggest-next` directly when you want to
point at an arbitrary scan file or override the target metadata.

It turns parsed nmap results into a service-based, prioritized methodology
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
  --target 10.10.10.5 \
  --host target.htb \
  --domain target.htb \
  -o outputs/next.md

# Force a specific parser
cpts-tools suggest-next -i scans/target.nmap  --input-format normal   --target 10.10.10.5
cpts-tools suggest-next -i scans/target.gnmap --input-format grepable --target 10.10.10.5
cpts-tools suggest-next -i scans/target.xml   --input-format xml      --target 10.10.10.5
```

The simplest invocation derives the target IP from the scan and prints Markdown to
stdout:

```bash
cpts-tools suggest-next -i scans/target.xml
```

Excerpt of the default `md` output:

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
Kerberos, MSSQL, MySQL, RDP, WinRM, SNMP, NFS. Open ports without a workflow are
listed under an **Unmapped Services** section so nothing is silently dropped.

#### Obsidian vault output

`--output-format obsidian` writes a small Obsidian-friendly vault folder instead of a
single Markdown file. The directory passed via `-o` is created (and intermediate
parents) if it does not already exist.

```bash
cpts-tools suggest-next \
  -i scans/target \
  --target 10.10.10.5 \
  --host target.htb \
  --domain target.htb \
  --output-format obsidian \
  -o notes/target
```

Generated layout:

```text
notes/target/
├── index.md          # MOC: frontmatter, scope, detected services, prioritized
│                     # wikilinks to each service note, optional report draft
├── services/
│   ├── smb.md        # frontmatter + Checklist / Commands / Expected output /
│   ├── http.md       # Verification / Troubleshooting / Report note / Related
│   ├── rdp.md
│   └── …             # one per detected & mapped service
└── unmapped.md       # only present when the scan has open ports without a workflow
```

- Filenames use the lowercase canonical service ID (`smb.md`, `winrm.md`).
- Cross-references render as aliased wikilinks: `[[services/smb|SMB]]`,
  `[[services/winrm|WinRM]]` — paths are stable and machine-friendly, while the
  alias keeps the rendered text human-friendly.
- Each note carries YAML frontmatter (`title`, `target`, `service`, `priority`,
  `status: in-progress`, tags) so Obsidian dataview / search queries work
  immediately.

By default the command refuses to overwrite existing files in the vault directory.
Pass `--force` to overwrite, or point `-o` at an empty/new directory. Files in the
target directory that the tool does not generate are left untouched.

```bash
# Re-render and overwrite previously generated notes
cpts-tools suggest-next -i scans/target --output-format obsidian -o notes/target --force
```

The `md` default behavior (single Markdown file, optional `-o`) is unchanged.

`--output-format` currently accepts `md` and `obsidian`; the option is scaffolded
so future releases can add `json` output without breaking the CLI shape.

## Development

Run syntax checks and tests:

```bash
python -m compileall src tests
python -m pytest
```
