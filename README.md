# reconlab

Minimal Python CLI helpers for authorized penetration-testing lab work. The project focuses on lab organization, scan parsing, and reporting workflows. It does not include exploit automation and is not intended for use against real third-party systems.

## Install

### From PyPI (recommended)

```bash
pipx install reconlab        # isolated install, recommended for CLI tools
# or:
pip install reconlab         # if you already manage your own Python env
```

### From source (for development)

```bash
git clone https://github.com/0xsl0th/reconlab.git
cd reconlab
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Commands at a glance

| Command | What it does |
|---------|--------------|
| `workspace init` | Scaffold a target folder, metadata file, and a richer report scaffold. |
| `workspace suggest` | Generate methodology from `scans/` - merges every scan file by default. |
| `workspace status` | Summarize a workspace - scans, methodology freshness, findings, web findings, and the next step. |
| `workspace ingest-web` | Merge every feroxbuster / gobuster / DirBuster output in a workspace's `web/` folder into one table. |
| `workspace check` | Lint `report.md` for wrap-up readiness - unfilled findings and sections. Exits non-zero on issues. |
| `finding add` / `finding list` | Capture findings into `report.md`; print the current findings table. |
| `workflow show` / `workflow list` | Print one workflow as Markdown / list the workflow registry - no scan or workspace needed. |
| `make-hosts` | Suggest an `/etc/hosts` entry - workspace-aware (pulls hostnames from scan output and metadata) with a manual no-workspace fallback. Read-only. |
| `vhost-suggest` | For each hostname discovered in scans (ssl-cert SANs, http-title redirects, SMB FQDN), print a `curl` probe and a `gobuster` enumeration command. Read-only. |
| `parse-nmap` | Tabular summary of open services from an nmap XML scan. |
| `parse-web` | Tabular summary of feroxbuster / gobuster / DirBuster output (text or JSON). |
| `suggest-next` | Methodology generator over an explicit scan file (underlies `workspace suggest`). |

Run `reconlab --help` (or `reconlab <command> --help`) for full option
lists, or `reconlab --version` to print the installed version.

## Lab session walkthrough

End-to-end flow for a typical lab target. Replace placeholders with the
real values your lab gives you.

```bash
# 1. Scaffold a workspace with metadata baked in. Init prints a suggested
#    /etc/hosts line built from --ip / --host / --domain - paste the echo
#    command it shows to map the hostname locally. Does NOT touch any file.
reconlab workspace init target \
  --ip <ip> \
  --host <host> \
  --domain <domain> \
  --platform lab

cd target

# 2. Run nmap into the workspace's scans/ folder.
sudo nmap -sV -sC -p- -oA scans/initial <ip>

# 3. (Optional) Re-run make-hosts to pick up hostnames discovered by the scan:
#    ssl-cert SANs, http-title redirects, SMB FQDN. Skip if no new hostnames.
reconlab make-hosts

# 4. Generate prioritized, service-by-service methodology as an Obsidian vault.
#    Metadata from the workspace (target IP / host / domain) is filled in
#    automatically - no need to repeat the flags.
reconlab workspace suggest

# 5. Open notes/methodology/index.md in Obsidian (or any Markdown editor).
#    Work through the per-service checklists; capture screenshots into
#    screenshots/, recovered files into loot/, credentials into creds/.

# 6. Record findings into report.md as you go. The first call replaces the
#    placeholder finding; later calls auto-increment the finding number.
reconlab finding add \
  --title "SMB null session enabled" \
  --severity high \
  --service smb \
  --port 445 \
  --evidence screenshots/01-null-session.png

reconlab finding list   # quick check of what is in the report so far
```

Layout produced by `workspace init`:

```text
target/
├── .reconlab.json    # target metadata (ip, host, domain, platform)
├── report.md           # engagement report scaffold with frontmatter
├── scans/              # raw nmap output (xml/nmap/gnmap)
├── screenshots/        # one set per finding
├── loot/               # recovered files (sanitized before report)
├── notes/              # working notes + generated methodology vault
├── exploits/           # adapted exploit code with attribution
└── creds/              # recovered credentials - gitignored
```

After `workspace suggest`, `notes/methodology/` contains an Obsidian-friendly
vault with one MOC (`index.md`) and one note per detected service.

## Usage

### Parse nmap XML

```bash
reconlab parse-nmap scans/target.xml

# JSON for piping to jq
reconlab parse-nmap scans/target.xml --output-format json | jq '.[] | select(.port=="445")'
```

Example output:

```text
Host  Names   Port  Proto  Service  Product  Version
----  ------  ----  -----  -------  -------  -------
<ip>  <host>  80    tcp    http     nginx    1.18.0
```

### Parse feroxbuster / gobuster / DirBuster output

`parse-web` ingests web content-discovery output and prints a clean
Status/Method/Size/URL table. It auto-detects feroxbuster text, feroxbuster
`--json`, gobuster text, and DirBuster (OWASP) report formats, strips ANSI
colours, and inlines redirect targets into the URL column.

```bash
# Auto-detect the format
reconlab parse-web outputs/feroxbuster.txt
reconlab parse-web outputs/feroxbuster.json
reconlab parse-web outputs/gobuster.txt
reconlab parse-web outputs/dirbuster.txt

# Force a specific parser
reconlab parse-web outputs/scan.txt --input-format feroxbuster
reconlab parse-web outputs/scan.txt --input-format dirbuster

# Filter to specific status codes:
#   --status pre-filters BEFORE rendering (so the table widths stay aligned and the
#   filter applies before --output-format json serializes). For simple table
#   filtering on a single file, plain grep on the rendered output works too -
#   each data row starts with the 3-digit status code.
reconlab parse-web outputs/feroxbuster.txt --status 200,301,403
reconlab parse-web outputs/feroxbuster.txt | grep -E '^200 '
reconlab parse-web outputs/feroxbuster.txt | grep -E '^[23][0-9]{2} '   # all 2xx + 3xx
reconlab parse-web outputs/feroxbuster.txt | grep -Ev '^404 '            # exclude 404 noise

# JSON for piping to jq (grep does not understand JSON - use jq or --status instead)
reconlab parse-web outputs/dirs.txt --output-format json | jq '.[] | .url'
reconlab parse-web outputs/dirs.txt --output-format json \
  | jq '.[] | select(.status == "200") | .url'
```

Example output:

```text
Status  Method  Size  Words  Lines  URL
------  ------  ----  -----  -----  ----------------------------------
200     GET     1234  46     4      http://<ip>/admin
301     GET     0     0      0      http://<ip>/login -> /login/
403     GET     287   12     2      http://<ip>/.git
200     GET     4567  62     8      http://<ip>/api/users
```

gobuster doesn't track word/line counts, so those columns show `-` for gobuster
input. DirBuster reports don't record size / words / lines at all, so those
three columns are all `-` for DirBuster input; URLs are reconstructed by
prefixing the base target URL (parsed from the report header) onto each
discovered path. Feroxbuster's `--json` format is parsed as newline-delimited
JSON, with non-`response` entries (scan-config, report) filtered out.

### Make an `/etc/hosts` entry

`make-hosts` is a read-only helper. It prints the line you should add to
`/etc/hosts` plus a ready-to-paste shell command. It never modifies any file.

#### Workspace mode (default)

Run with no IP/hostname args inside (or pointed at) a workspace. The command
reads `.reconlab.json` for the target IP plus any `target_host` / `domain`,
walks every nmap XML scan in `scans/`, and pulls hostname candidates from:

- `<hostnames>` (reverse DNS / user-supplied)
- `ssl-cert` script: subject `commonName` and Subject Alternative Names
  (DNS entries; wildcards and IP SANs are filtered out)
- `http-title` script: hostnames in "Did not follow redirect to ..." lines
- `smb-os-discovery` script: `fqdn` field

Candidates are deduplicated case-insensitively (first-seen casing wins) and
the merged sources are shown so you can see *why* each hostname was suggested.

```bash
cd ~/labs/target
reconlab make-hosts
# or: reconlab make-hosts ~/labs/target
```

Sample output for a workspace whose scans contain ssl-cert + smb-os-discovery
script results:

```text
# Workspace: /home/you/labs/target
# Target IP: <ip>
# Hostname candidates:
#   <host>     (dns, ssl-cert CN, ssl-cert SAN, smb-os-discovery FQDN)
#   <host-2>   (http-title redirect)
#   <host-3>   (ssl-cert SAN)

# Add this to /etc/hosts:
<ip> <host> <host-2> <host-3>

# Or run:
echo "<ip> <host> <host-2> <host-3>" | sudo tee -a /etc/hosts
```

If `.reconlab.json` has no `target_ip` set, pass `--target-ip <ip>` to
override for this run. If no hostname candidates are found, the IP line is
still printed so you can add hostnames manually.

#### Manual form (no workspace)

Pass an IP followed by one or more hostnames when you just want to format a
line without involving a workspace:

```bash
reconlab make-hosts <ip> <host> dev.corp.local Dev.corp.local DEV.corp.local
```

Or the equivalent flag form:

```bash
reconlab make-hosts \
  --ip <ip> \
  --host <host> \
  --aliases dev.corp.local Dev.corp.local DEV.corp.local
```

In the flag form, the first value after `--aliases` is consumed by the flag and
any further positional arguments are appended as additional aliases - so the
shell-natural `--aliases a b c` syntax works. Repeating the flag
(`--aliases a --aliases b`) is also supported. Hostname casing is preserved
exactly as typed. Whether workspace mode or manual form runs is decided by the
first positional: an IPv4 address routes to manual; anything else (or no args)
routes to workspace mode.

### Enumerate discovered vhosts

After `make-hosts` reads ssl-cert SANs, http-title redirects, and SMB FQDN
from your scan, the natural next step is to probe each newly-discovered
hostname as a virtual host. `vhost-suggest` prints exactly the commands you
need - one `curl` probe and one `gobuster` enumeration line per hostname -
using the `Host` header so the requests go to the target IP directly and
do not depend on `/etc/hosts` resolution.

```bash
# From inside the workspace, or pointed at one explicitly.
reconlab vhost-suggest
reconlab vhost-suggest ~/labs/target
reconlab vhost-suggest --target-ip <ip>     # override metadata IP for the run
```

The metadata `target_host` (and its FQDN form when `--domain` is set) is
excluded - that is your primary host, already mapped. Only the newly-
discovered hostnames get suggestions. Read-only - reconlab never sends any
requests itself.

```text
# Workspace: /home/op/labs/target
# Target IP: <ip>
# Discovered vhosts (excluding metadata target_host '<host>'):

# <host-2> (http-title redirect)
curl -I -H 'Host: <host-2>' http://<ip>/
gobuster dir -u http://<ip>/ -H 'Host: <host-2>' -w <wordlist> -o web/<host-2>.txt

# <host-3> (ssl-cert SAN)
curl -I -H 'Host: <host-3>' http://<ip>/
gobuster dir -u http://<ip>/ -H 'Host: <host-3>' -w <wordlist> -o web/<host-3>.txt
```

If scans/ contains only non-XML output (`.nmap` / `.gnmap`, no `.xml`),
the command prints the same XML-only hint as `make-hosts` since the script
data needed for vhost discovery only exists in XML.

### Manage a lab workspace

`workspace init` scaffolds a target folder with a richer report template and
persists target metadata so downstream commands inherit it.

```bash
reconlab workspace init target \
  --ip <ip> \
  --host <host> \
  --domain <domain> \
  --platform lab \
  -o ~/labs
```

`workspace suggest` merges every scan file in `scans/` (oldest → newest) and
generates methodology into `notes/methodology/` (Obsidian vault by default),
`notes/methodology.md` (`--output-format md`), or `notes/methodology.json`
(`--output-format json`):

```bash
# From inside the workspace, no flags needed.
reconlab workspace suggest

# Or explicitly point at a workspace.
reconlab workspace suggest ~/labs/target --output-format md --force
```

Multi-scan behavior:

- A typical engagement runs a TCP full scan, a UDP top-N scan, and a targeted
  `-sV -sC` rescan. Drop all three into `scans/`; methodology generation will
  union open ports across them and merge service metadata.
- Records are keyed by `(host, port, proto)`. When the same port appears in
  more than one scan, the **most recent non-placeholder value wins** for
  service name, product, and version - so a later `-sV` overrides an earlier
  banner-only scan, but an unscanned re-discovery cannot erase real data
  captured earlier.
- Pass `--latest` to revert to single-scan mode (most-recently-modified file
  only). Useful if older scans in `scans/` are stale or experimental.

Re-running refuses to overwrite the previous methodology unless `--force` is
passed; unrelated files in the workspace are never touched.

### Check workspace status

`workspace status` prints a one-screen summary of where a workspace stands -
scan count, whether methodology has been generated (and whether it is stale
relative to `scans/`), recorded findings by severity, and a single suggested
next step.

```bash
# From inside the workspace, or point at one explicitly.
reconlab workspace status
reconlab workspace status ~/labs/target
```

```text
Workspace: target
Path:      /home/op/labs/target

  Target       <ip> · <host> · <domain>
  Platform     lab
  Scans        1 file (latest: initial.xml)
  Methodology  notes/methodology/  - STALE (newer scans present)
  Findings     1 recorded - 1 High

Next: methodology is stale relative to scans/. Re-run:
      reconlab workspace suggest --force
```

The **Next** block is state-driven: a short description explains the
situation, and any concrete commands appear on indented lines below so
they are easy to copy-paste. It points at `workspace suggest` when no
methodology exists yet, flags a stale methodology once newer scans land, and
nudges toward `finding add` after methodology is in place. It never modifies
the workspace - `workspace status` is read-only.

### Ingest web content-discovery output

`workspace init` now creates a `web/` folder alongside `scans/`. Drop
feroxbuster (text or `--json`) or gobuster output there, and
`workspace ingest-web` merges every file into one deduplicated table -
parallel to how `workspace suggest` merges every nmap scan in `scans/`.

```bash
# After running content discovery against an HTTP service:
feroxbuster -u http://<ip> --json -o ~/labs/target/web/initial.json
gobuster dir -u http://<ip> -w wordlist.txt -o ~/labs/target/web/dir.txt

# From inside the workspace, or point at one explicitly:
reconlab workspace ingest-web
reconlab workspace ingest-web ~/labs/target

# Filter to specific status codes:
reconlab workspace ingest-web --status 200,301,403
```

Findings deduplicate by `(method, status, URL)`; when the same URL+method+
status appears in multiple files, the most recent non-placeholder size /
word / line count wins. `workspace status` shows the merged count alongside
scans and findings, and the **Next** hint nudges toward `ingest-web` once
web outputs are present.

### Check report readiness

`workspace check` lints the workspace's `report.md` and flags the scaffold
placeholders still left unfilled - per-finding fields (Severity, Description,
Evidence, Impact, Remediation) and the Executive Summary. It exits non-zero
when issues remain, so it works as a pre-handover gate or a CI step.

```bash
# From inside the workspace, or point at one explicitly.
reconlab workspace check
reconlab workspace check ~/labs/target
```

```text
Report check: /home/op/labs/target/report.md

Report:
  - Executive Summary is still the scaffold placeholder.

Findings:
  Finding 1 - SMB null session enabled
    - **Impact** is still a scaffold placeholder
    - **Remediation** is still a scaffold placeholder

3 issues found - fill these in before handing the report over.
```

`finding add` fills in Severity, Affected, and (with `--service`) Description,
but Impact and Remediation are always left for you - `workspace check` is the
reminder that they, and the Executive Summary, still need attention. Like
`workspace status`, it is read-only.

### Record findings into the report

`finding add` appends a structured finding block to `report.md` inside the
workspace. The first call replaces the placeholder `### Finding 1 - _Title_`
left there by `workspace init`; subsequent calls auto-increment the finding
number after the highest existing one.

```bash
reconlab finding add \
  --title "SMB null session enabled" \
  --severity high \
  --service smb \
  --port 445 \
  --evidence screenshots/01-shares.png \
  --evidence loot/null-session-listing.txt
```

What `finding add` does:

- Reads `.reconlab.json` and pre-fills `Affected:` with the workspace's
  target IP and hostname.
- If `--service` matches a known workflow (`smb`, `http`, ...), seeds the
  `Description:` from the workflow's report-note (with `[TARGET_IP]` /
  `[TARGET_HOST]` / `[DOMAIN]` substituted) and adds a
  `**Methodology:** see [[notes/methodology/services/<service>]]` cross-link.
- `--description` overrides the workflow seed when you want custom text.
- Each `--evidence PATH` adds a bullet under `Evidence:`. Repeat the flag for
  multiple files (`--evidence a.png --evidence b.png`).
- Severity is restricted to `critical | high | medium | low | info`.

`finding list` prints the current findings as a one-line-per-finding table -
handy for sanity-checking what is captured so far without opening the file.
Severity is color-coded in the terminal (Critical bold-red, High bright-red,
Medium yellow, Low cyan, Info dim); ANSI codes are auto-stripped when output
is piped to a file or another command.

```bash
reconlab finding list
reconlab finding list ~/labs/target

# Filter by severity (comma-separated, case-insensitive)
reconlab finding list --severity high,critical
reconlab finding list --severity medium

# JSON for piping to jq (filter applies before serialization)
reconlab finding list --output-format json | jq '.[] | .title'
reconlab finding list --severity high,critical --output-format json
```

```text
#  Severity  Title                        Service:Port
-  --------  ---------------------------  ------------
1  High      SMB null session enabled     smb:445
2  Medium    HTTP debug endpoint exposed  http:80
```

### Browse the workflow registry

`workflow list` and `workflow show` expose the workflow registry directly -
useful for "remind me what to check for LDAP" or for picking a starting point
on a target you haven't scanned yet. Neither command needs a workspace or a
scan file.

Workflows fall into three categories:

- **`service-enum`** - per-service enumeration methodology (SMB, HTTP, LDAP, …).
  These are what `suggest-next` / `workspace suggest` auto-select from a scan.
- **`post-foothold`** - what to do once you have a shell or a valid credential:
  `linux-privesc`, `windows-privesc`, `ad-foothold`.
- **`lateral-movement`** - `pivoting`: tunneling and internal network access.

Post-foothold and lateral-movement workflows have no ports, so a scan never
auto-selects them - reach them with `workflow show`.

```bash
reconlab workflow list
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
reconlab workflow show smb
reconlab workflow show linux-privesc

# Or substitute target metadata while rendering
reconlab workflow show ad-foothold --domain <domain>
```

The Markdown is the same per-workflow content that `workspace suggest` and
`suggest-next` write into the methodology document. Those two commands also
append an **After a Foothold** footer pointing at the post-foothold workflows,
so the generated methodology carries you past initial access.

### Suggest the next steps from an nmap scan

`suggest-next` is the underlying methodology generator. For the typical case
(one workspace, drop a scan into `scans/`, get a vault back) prefer
`reconlab workspace suggest` - it picks up the latest scan and the workspace
metadata automatically. Reach for `suggest-next` directly when you want to
point at an arbitrary scan file or override the target metadata.

It turns parsed nmap results into a service-based, prioritized methodology
document. Each detected service gets a checklist, command table, expected output,
verification steps, troubleshooting matrix, and a draft report note. Lab placeholders
(`[USER]`, `[PASS]`, `[LHOST]`, `[LPORT]`) are preserved for the operator to fill in.

Supported input formats:

- `xml` - nmap XML (`-oX` or `-oA`); the most reliable parser.
- `normal` - human-readable nmap output (`.nmap` files from `-oN` or `-oA`).
- `grepable` - grepable nmap output (`.gnmap` files from `-oG` or `-oA`).
- `auto` (default) - infers from the file extension; if the path has no extension,
  it is treated as an `nmap -oA` basename and the matching sibling file is probed
  in `xml → normal → grepable` priority.

```bash
# Auto-detect: scans/target resolves to scans/target.xml if present,
# otherwise scans/target.nmap, otherwise scans/target.gnmap.
reconlab suggest-next \
  -i scans/target \
  --input-format auto \
  --target <ip> \
  --host <host> \
  --domain <domain> \
  -o outputs/next.md

# Force a specific parser
reconlab suggest-next -i scans/target.nmap  --input-format normal   --target <ip>
reconlab suggest-next -i scans/target.gnmap --input-format grepable --target <ip>
reconlab suggest-next -i scans/target.xml   --input-format xml      --target <ip>
```

The simplest invocation derives the target IP from the scan and prints Markdown to
stdout:

```bash
reconlab suggest-next -i scans/target.xml
```

Excerpt of the default `md` output:

```markdown
# Methodology - <ip>

## Detected Services

| Port | Proto | Service | Product | Version |
|------|-------|---------|---------|---------|
| 445  | tcp   | microsoft-ds | Samba | 4.15.0 |
| 3389 | tcp   | ms-wbt-server | - | - |

## SMB (139/445) - Share & RPC Enumeration

### Checklist
- [ ] Fingerprint SMB dialect and signing posture.
- [ ] Attempt null-session share listing.
...
```

Supported service-enum workflows in this release: SMB, HTTP, HTTPS, FTP, SSH,
DNS, SMTP, LDAP, Kerberos, MSSQL, MySQL, Oracle, RDP, WinRM, SNMP, NFS, rsync,
Redis, VNC, IMAP/POP3 (20 total), plus
three post-foothold workflows - `linux-privesc`, `windows-privesc`,
`ad-foothold` - and one lateral-movement workflow, `pivoting`. Run
`reconlab workflow list` for the live registry with
categories, priorities, and port mappings. Open ports without a service-enum
workflow are listed under an **Unmapped Services** section so nothing is
silently dropped.

#### Obsidian vault output

`--output-format obsidian` writes a small Obsidian-friendly vault folder instead of a
single Markdown file. The directory passed via `-o` is created (and intermediate
parents) if it does not already exist.

```bash
reconlab suggest-next \
  -i scans/target \
  --target <ip> \
  --host <host> \
  --domain <domain> \
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
  `[[services/winrm|WinRM]]` - paths are stable and machine-friendly, while the
  alias keeps the rendered text human-friendly.
- Each note carries YAML frontmatter (`title`, `target`, `service`, `priority`,
  `status: in-progress`, tags) so Obsidian dataview / search queries work
  immediately.

By default the command refuses to overwrite existing files in the vault directory.
Pass `--force` to overwrite, or point `-o` at an empty/new directory. Files in the
target directory that the tool does not generate are left untouched.

```bash
# Re-render and overwrite previously generated notes
reconlab suggest-next -i scans/target --output-format obsidian -o notes/target --force
```

The `md` default behavior (single Markdown file, optional `-o`) is unchanged.

#### JSON output

`--output-format json` writes a single structured JSON document instead of
Markdown or a vault: target metadata, detected and unmapped services, and the
full prioritized per-workflow methodology (checklists, commands, troubleshooting,
report notes) as data. Like `md`, it prints to stdout when `-o` is omitted.

```bash
# To a file, or piped into jq for scripting.
reconlab suggest-next -i scans/target --output-format json -o outputs/methodology.json
reconlab suggest-next -i scans/target --output-format json | jq '.workflows[].service_id'
```

Target placeholders (`[TARGET_IP]`, `[TARGET_HOST]`, `[DOMAIN]`) are substituted;
operator placeholders (`[USER]`, `[PASS]`, ...) are left intact for downstream
tooling. `--output-format` accepts `md`, `json`, and `obsidian`.

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
