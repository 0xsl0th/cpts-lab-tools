# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.1] - 2026-05-17

### Changed

- **Top-level and subgroup `--help` pages now also end with `Examples`
  blocks.** 0.9.0 added Examples to every leaf command but left
  `reconlab --help`, `reconlab workspace --help`, `reconlab finding --help`,
  and `reconlab workflow --help` without one. They now each include a brief
  block of representative invocations, matching the leaf-command pattern.

## [0.9.0] - 2026-05-17

### Changed

- **Every command's `--help` now ends with an `Examples` block** showing 2-5
  concrete invocations covering its main usage patterns. Covers the top-level
  commands (`parse-nmap`, `parse-web`, `make-hosts`, `suggest-next`) plus
  every `workspace`, `finding`, and `workflow` subcommand. Self-sufficient
  `--help` means users no longer have to consult the README to discover the
  common command shapes.

### Internal

- **Bumped `actions/checkout` v4 -> v6 and `actions/setup-python` v5 -> v6**
  in both `publish.yml` and `tests.yml`. The previous majors ran on Node.js
  20, which GitHub will force to Node 24 by default on 2026-06-02 and remove
  entirely on 2026-09-16. The new majors support Node 24 natively, silencing
  the deprecation warnings on every workflow run.

## [0.8.0] - 2026-05-17

### Changed

- **`make-hosts` is now workspace-aware.** Run with no IP/hostname args (or
  pointed at a workspace path) and it pulls hostname candidates from
  `.reconlab.json` and every nmap XML scan in `scans/` - extracting reverse
  DNS, `ssl-cert` Subject CN and SAN DNS entries, `http-title` redirects, and
  `smb-os-discovery` FQDN. Candidates are deduplicated case-insensitively with
  merged sources shown so you can see why each hostname was suggested. The
  manual no-workspace forms (`make-hosts IP HOSTNAMES...` and
  `--ip/--host/--aliases`) are unchanged and trigger automatically when the
  first positional is an IPv4 address. A new `--target-ip` flag overrides the
  workspace's metadata IP for a single run.
- **`workspace init` now prints a suggested `/etc/hosts` line at the end of
  init output** when `--ip` is set together with `--host`, including the
  FQDN form (`host.domain`) when `--domain` is also passed. Removes the
  need to re-type IP/host just to format the hosts entry. Still read-only -
  reconlab never modifies `/etc/hosts` itself.
- **`make-hosts` workspace mode now prints a tip when `scans/` has only
  non-XML files** (`.nmap` / `.gnmap` only, no `.xml`). NSE script output
  only exists in structured form in XML, so users dumping text-only nmap
  output were silently missing the ssl-cert / http-title / smb-os-discovery
  enrichment. The tip nudges them toward `nmap -oA <basename>`. Silent when
  XML is present or `scans/` is empty.

## [0.7.0] - 2026-05-15

### Added

- **`workspace ingest-web`** - closes the asymmetry where the workspace only
  ingested nmap. A new `web/` folder is created on `workspace init`; drop
  feroxbuster (text or `--json`) and gobuster output files there, and
  `workspace ingest-web` merges every file into one deduplicated table
  (`--status` filter, redirect inlined). `workspace status` now shows the
  merged web-finding count and its **Next** hint surfaces `ingest-web` when
  relevant. Mirrors how `workspace suggest` merges multiple scans.

## [0.6.0] - 2026-05-15

### Removed

- **`report-init` and `obsidian-note` commands** - both were deprecated in 0.4.0
  with a removal promise. Migrate to `workspace init` (replaces `report-init`)
  and `workspace init` + `workspace suggest` (replaces `obsidian-note`). The
  internal `_warn_deprecated` helper goes away with them since no callers
  remain.

## [0.5.0] - 2026-05-15

### Added

- **Five new service-enum workflows** - Oracle TNS (1521), IMAP/POP3 (110/143/
  993/995), rsync (873), Redis (6379), and VNC (5900). Each provides the full
  workflow shape - checklist, commands, expected output, verification,
  troubleshooting, report note - with lab-safe placeholders. Three are grounded
  in the field-manual reference (Oracle, IMAP/POP3, rsync); two cover common
  pentest methodology (Redis, VNC). The registry now covers 20 service-enum
  workflows.
- **`parse-web` command** - ingests feroxbuster (text or `--json`) and
  gobuster text output and prints a clean Status/Method/Size/URL table,
  parallel to `parse-nmap`. Auto-detects the format, strips ANSI colors,
  inlines redirect targets into the URL column, and supports `--status`
  filtering. Fills the gap that the workspace previously only ingested nmap.

## [0.4.0] - 2026-05-15

### Added

- **Report check** - `workspace check` lints a workspace's `report.md` for
  wrap-up readiness, flagging unfilled scaffold placeholders in findings
  (Severity, Description, Evidence, Impact, Remediation) and the Executive
  Summary. Exits non-zero when issues remain, so it can gate a handover or CI.
- **PyPI distribution** - the project is now packaged for PyPI with full
  metadata (license, classifiers, URLs) and a trusted-publishing GitHub
  Actions workflow that auto-publishes on each GitHub release. Install via
  `pipx install reconlab` or `pip install reconlab`. MIT licensed.

### Changed

- **Renamed the project** from `cpts-lab-tools` to `reconlab`. The distribution
  name, import package, CLI command, and workspace metadata file
  (`.cpts-tools.json` → `.reconlab.json`) all share the new name. Any existing
  local workspaces need their `.cpts-tools.json` renamed to `.reconlab.json` by
  hand. GitHub redirects old URLs.

## [0.3.0] - 2026-05-14

### Added

- **Workspace status** - `workspace status` summarizes a workspace at a glance:
  scan count and latest scan, whether methodology has been generated and whether
  it is stale relative to `scans/`, recorded findings by severity, and a single
  state-driven "next step" hint. Read-only - it never modifies the workspace.
- **Version flag** - `reconlab --version` prints the installed version and
  exits.
- **JSON output** - `suggest-next` and `workspace suggest` accept
  `--output-format json`, emitting a structured JSON document (target metadata,
  detected/unmapped services, and the full per-workflow methodology) for
  scripting. `workspace suggest --output-format json` writes
  `notes/methodology.json`.

### Deprecated

- `report-init` and `obsidian-note` are deprecated in favor of `workspace init`
  / `workspace suggest`. Both still work, but now print a deprecation notice on
  stderr and are planned for removal in a future release.

## [0.2.0] - 2026-05-14

### Added

- **Workspace lifecycle** - `workspace init` scaffolds a target folder with
  persisted metadata and a report scaffold; `workspace suggest` generates
  methodology directly from a workspace's `scans/` folder.
- **Multi-format Nmap parsing** - accepts XML, normal (`.nmap`), and grepable
  (`.gnmap`) output, with auto-detection from the file extension or `-oA`
  basename.
- **Multi-scan merge** - `workspace suggest` unions open ports across every
  scan in `scans/` by default, keyed by `(host, port, proto)`, with the most
  recent non-placeholder service data winning; `--latest` restores single-scan
  mode.
- **Methodology output** - render methodology as a single Markdown file or as
  an Obsidian-friendly vault (MOC index plus one cross-linked note per service).
- **Workflow registry** - inspectable via `workflow list` / `workflow show`,
  organized into `service-enum`, `post-foothold`, and `lateral-movement`
  categories; 15 service workflows plus `linux-privesc`, `windows-privesc`,
  `ad-foothold`, and `pivoting`.
- **Findings capture** - `finding add` / `finding list` record structured,
  severity-tagged findings into a workspace's `report.md`.
- **CI and linting** - GitHub Actions runs `ruff check` and `pytest` on every
  push and pull request across Python 3.11 and 3.13; Ruff added as a dev
  dependency with a basic rule set.

[0.7.0]: https://github.com/0xsl0th/reconlab/releases/tag/v0.7.0
[0.6.0]: https://github.com/0xsl0th/reconlab/releases/tag/v0.6.0
[0.5.0]: https://github.com/0xsl0th/reconlab/releases/tag/v0.5.0
[0.4.0]: https://github.com/0xsl0th/reconlab/releases/tag/v0.4.0
[0.3.0]: https://github.com/0xsl0th/reconlab/releases/tag/v0.3.0
[0.2.0]: https://github.com/0xsl0th/reconlab/releases/tag/v0.2.0
