# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-05-15

### Added

- **Report check** — `workspace check` lints a workspace's `report.md` for
  wrap-up readiness, flagging unfilled scaffold placeholders in findings
  (Severity, Description, Evidence, Impact, Remediation) and the Executive
  Summary. Exits non-zero when issues remain, so it can gate a handover or CI.
- **PyPI distribution** — the project is now packaged for PyPI with full
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

- **Workspace status** — `workspace status` summarizes a workspace at a glance:
  scan count and latest scan, whether methodology has been generated and whether
  it is stale relative to `scans/`, recorded findings by severity, and a single
  state-driven "next step" hint. Read-only — it never modifies the workspace.
- **Version flag** — `reconlab --version` prints the installed version and
  exits.
- **JSON output** — `suggest-next` and `workspace suggest` accept
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

- **Workspace lifecycle** — `workspace init` scaffolds a target folder with
  persisted metadata and a report scaffold; `workspace suggest` generates
  methodology directly from a workspace's `scans/` folder.
- **Multi-format Nmap parsing** — accepts XML, normal (`.nmap`), and grepable
  (`.gnmap`) output, with auto-detection from the file extension or `-oA`
  basename.
- **Multi-scan merge** — `workspace suggest` unions open ports across every
  scan in `scans/` by default, keyed by `(host, port, proto)`, with the most
  recent non-placeholder service data winning; `--latest` restores single-scan
  mode.
- **Methodology output** — render methodology as a single Markdown file or as
  an Obsidian-friendly vault (MOC index plus one cross-linked note per service).
- **Workflow registry** — inspectable via `workflow list` / `workflow show`,
  organized into `service-enum`, `post-foothold`, and `lateral-movement`
  categories; 15 service workflows plus `linux-privesc`, `windows-privesc`,
  `ad-foothold`, and `pivoting`.
- **Findings capture** — `finding add` / `finding list` record structured,
  severity-tagged findings into a workspace's `report.md`.
- **CI and linting** — GitHub Actions runs `ruff check` and `pytest` on every
  push and pull request across Python 3.11 and 3.13; Ruff added as a dev
  dependency with a basic rule set.

[0.4.0]: https://github.com/0xsl0th/reconlab/releases/tag/v0.4.0
[0.3.0]: https://github.com/0xsl0th/reconlab/releases/tag/v0.3.0
[0.2.0]: https://github.com/0xsl0th/reconlab/releases/tag/v0.2.0
