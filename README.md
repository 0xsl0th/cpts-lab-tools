# cpts-lab-tools

Minimal Python CLI helpers for authorized penetration-testing lab work. The project focuses on lab organization, scan parsing, and reporting workflows. It does not include exploit automation and is not intended for use against real third-party systems.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Commands at a glance

| Command | What it does |
|---------|--------------|
| `workspace init` | Scaffold a target folder, metadata file, and a richer report scaffold. |
| `workspace suggest` | Generate methodology from `scans/` — merges every scan file by default. |
| `workspace status` | Summarize a workspace — scans, methodology freshness, findings, and the next step. |
| `finding add` / `finding list` | Capture findings into `report.md`; print the current findings table. |
| `workflow show` / `workflow list` | Print one workflow as Markdown / list the workflow registry — no scan or workspace needed. |
| `make-hosts` | Print an `/etc/hosts` entry plus a copy-paste shell command. Read-only. |
| `parse-nmap` | Tabular summary of open services from an nmap XML scan. |
| `suggest-next` | Methodology generator over an explicit scan file (underlies `workspace suggest`). |
| `report-init` / `obsidian-note` | Legacy single-target scaffolds; prefer `workspace init`. |

Run `cpts-tools --help` (or `cpts-tools <command> --help`) for full option
lists, or `cpts-tools --version` to print the installed version.

## Lab session walkthrough

End-to-end flow for a typical lab target. Replace placeholders with the
real values your lab gives you.

```bash
# 1. Scaffold a workspace with metadata baked in.
cpts-tools workspace init target \
  --ip 10.10.10.5 \
  --host app.corp.local \
  --domain corp.local \
  --platform lab

cd target

# 2. (Optional) Print the /etc/hosts entry and a copy-paste shell command.
#    Does NOT modify /etc/hosts — you run the printed command yourself.
cpts-tools make-hosts 10.10.10.5 app.corp.local

# 3. Run nmap into the workspace's scans/ folder.
sudo nmap -sV -sC -p- -oA scans/initial 10.10.10.5

# 4. Generate prioritized, service-by-service methodology as an Obsidian vault.
#    Metadata from the workspace (target IP / host / domain) is filled in
#    automatically — no need to repeat the flags.
cpts-tools workspace suggest

# 5. Open notes/methodology/index.md in Obsidian (or any Markdown editor).
#    Work through the per-service checklists; capture screenshots into
#    screenshots/, recovered files into loot/, credentials into creds/.

# 6. Record findings into report.md as you go. The first call replaces the
#    placeholder finding; later calls auto-increment the finding number.
cpts-tools finding add \
  --title "SMB null session enabled" \
  --severity high \
  --service smb \
  --port 445 \
  --evidence screenshots/01-null-session.png

cpts-tools finding list   # quick check of what is in the report so far
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
Host        Names           Port  Proto  Service  Product  Version
----------  --------------  ----  -----  -------  -------  -------
10.10.10.5  app.corp.local  80    tcp    http     nginx    1.18.0
```

### Make an `/etc/hosts` entry

`make-hosts` is a read-only helper. It prints the line you should add to
`/etc/hosts` plus a ready-to-paste shell command. It never modifies any file.

Positional form:

```bash
cpts-tools make-hosts 10.10.10.5 app.corp.local dev.corp.local Dev.corp.local DEV.corp.local
```

Output:

```text
# Add this to /etc/hosts:
10.10.10.5 app.corp.local dev.corp.local Dev.corp.local DEV.corp.local

# Or run:
echo "10.10.10.5 app.corp.local dev.corp.local Dev.corp.local DEV.corp.local" | sudo tee -a /etc/hosts
```

Flag form (equivalent output):

```bash
cpts-tools make-hosts \
  --ip 10.10.10.5 \
  --host app.corp.local \
  --aliases dev.corp.local Dev.corp.local DEV.corp.local
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
  --host app.corp.local \
  --domain corp.local \
  --platform lab \
  -o ~/labs
```

`workspace suggest` merges every scan file in `scans/` (oldest → newest) and
generates methodology into `notes/methodology/` (Obsidian vault by default) or
`notes/methodology.md` (with `--output-format md`):

```bash
# From inside the workspace, no flags needed.
cpts-tools workspace suggest

# Or explicitly point at a workspace.
cpts-tools workspace suggest ~/labs/target --output-format md --force
```

Multi-scan behavior:

- A typical engagement runs a TCP full scan, a UDP top-N scan, and a targeted
  `-sV -sC` rescan. Drop all three into `scans/`; methodology generation will
  union open ports across them and merge service metadata.
- Records are keyed by `(host, port, proto)`. When the same port appears in
  more than one scan, the **most recent non-placeholder value wins** for
  service name, product, and version — so a later `-sV` overrides an earlier
  banner-only scan, but an unscanned re-discovery cannot erase real data
  captured earlier.
- Pass `--latest` to revert to single-scan mode (most-recently-modified file
  only). Useful if older scans in `scans/` are stale or experimental.

Re-running refuses to overwrite the previous methodology unless `--force` is
passed; unrelated files in the workspace are never touched.

### Check workspace status

`workspace status` prints a one-screen summary of where a workspace stands —
scan count, whether methodology has been generated (and whether it is stale
relative to `scans/`), recorded findings by severity, and a single suggested
next step.

```bash
# From inside the workspace, or point at one explicitly.
cpts-tools workspace status
cpts-tools workspace status ~/labs/target
```

```text
Workspace: target
Path:      /home/op/labs/target

  Target       10.10.10.5 · app.corp.local · corp.local
  Platform     lab
  Scans        1 file (latest: initial.xml)
  Methodology  notes/methodology/  — STALE (newer scans present)
  Findings     1 recorded — 1 High

Next: scans/ changed since the methodology was generated — re-run `cpts-tools workspace suggest --force`.
```

The **Next** line is state-driven: it points at `workspace suggest` when no
methodology exists yet, flags a stale methodology once newer scans land, and
nudges toward `finding add` after methodology is in place. It never modifies
the workspace — `workspace status` is read-only.

### Record findings into the report

`finding add` appends a structured finding block to `report.md` inside the
workspace. The first call replaces the placeholder `### Finding 1 — _Title_`
left there by `workspace init`; subsequent calls auto-increment the finding
number after the highest existing one.

```bash
cpts-tools finding add \
  --title "SMB null session enabled" \
  --severity high \
  --service smb \
  --port 445 \
  --evidence screenshots/01-shares.png \
  --evidence loot/null-session-listing.txt
```

What `finding add` does:

- Reads `.cpts-tools.json` and pre-fills `Affected:` with the workspace's
  target IP and hostname.
- If `--service` matches a known workflow (`smb`, `http`, ...), seeds the
  `Description:` from the workflow's report-note (with `[TARGET_IP]` /
  `[TARGET_HOST]` / `[DOMAIN]` substituted) and adds a
  `**Methodology:** see [[notes/methodology/services/<service>]]` cross-link.
- `--description` overrides the workflow seed when you want custom text.
- Each `--evidence PATH` adds a bullet under `Evidence:`. Repeat the flag for
  multiple files (`--evidence a.png --evidence b.png`).
- Severity is restricted to `critical | high | medium | low | info`.

`finding list` prints the current findings as a one-line-per-finding table —
handy for sanity-checking what is captured so far without opening the file:

```text
#  Severity  Title                        Service:Port
-  --------  ---------------------------  ------------
1  High      SMB null session enabled     smb:445
2  Medium    HTTP debug endpoint exposed  http:80
```

### Browse the workflow registry

`workflow list` and `workflow show` expose the workflow registry directly —
useful for "remind me what to check for LDAP" or for picking a starting point
on a target you haven't scanned yet. Neither command needs a workspace or a
scan file.

Workflows fall into three categories:

- **`service-enum`** — per-service enumeration methodology (SMB, HTTP, LDAP, …).
  These are what `suggest-next` / `workspace suggest` auto-select from a scan.
- **`post-foothold`** — what to do once you have a shell or a valid credential:
  `linux-privesc`, `windows-privesc`, `ad-foothold`.
- **`lateral-movement`** — `pivoting`: tunneling and internal network access.

Post-foothold and lateral-movement workflows have no ports, so a scan never
auto-selects them — reach them with `workflow show`.

```bash
cpts-tools workflow list
```

```text
Category          ID               Display          Priority  Ports
----------------  ---------------  ---------------  --------  --------------------
service-enum      smb              SMB              10        139/tcp, 445/tcp
service-enum      http             HTTP             15        80/tcp, 8000/tcp, …
…
post-foothold     linux-privesc    Linux Privesc    50        -
post-foothold     windows-privesc  Windows Privesc  51        -
post-foothold     ad-foothold      AD Foothold      52        -
lateral-movement  pivoting         Pivoting         60        -
```

```bash
# Print one workflow (Markdown) to stdout with placeholders intact
cpts-tools workflow show smb
cpts-tools workflow show linux-privesc

# Or substitute target metadata while rendering
cpts-tools workflow show ad-foothold --domain corp.local
```

The Markdown is the same per-workflow content that `workspace suggest` and
`suggest-next` write into the methodology document. Those two commands also
append an **After a Foothold** footer pointing at the post-foothold workflows,
so the generated methodology carries you past initial access.

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
  --host app.corp.local \
  --domain corp.local \
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

Supported service-enum workflows in this release: SMB, HTTP, HTTPS, FTP, SSH,
DNS, SMTP, LDAP, Kerberos, MSSQL, MySQL, RDP, WinRM, SNMP, NFS (15 total), plus
three post-foothold workflows — `linux-privesc`, `windows-privesc`,
`ad-foothold` — and one lateral-movement workflow, `pivoting`. Run
`cpts-tools workflow list` for the live registry with
categories, priorities, and port mappings. Open ports without a service-enum
workflow are listed under an **Unmapped Services** section so nothing is
silently dropped.

#### Obsidian vault output

`--output-format obsidian` writes a small Obsidian-friendly vault folder instead of a
single Markdown file. The directory passed via `-o` is created (and intermediate
parents) if it does not already exist.

```bash
cpts-tools suggest-next \
  -i scans/target \
  --target 10.10.10.5 \
  --host app.corp.local \
  --domain corp.local \
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

Install the dev extras (`pytest` + `ruff`), then run syntax checks, lint, and
tests:

```bash
python -m pip install -e ".[dev]"
python -m compileall src tests
ruff check .
python -m pytest
```

GitHub Actions runs `ruff check .` and `pytest` on every push and pull request
across Python 3.11 and 3.13 (see `.github/workflows/tests.yml`).
