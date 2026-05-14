# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/0xsl0th/cpts-lab-tools/releases/tag/v0.2.0
