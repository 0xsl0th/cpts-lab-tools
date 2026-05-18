"""Parse web content-discovery output (feroxbuster, gobuster) into normalized rows.

`parse-web` reads feroxbuster (text or `--json`) or gobuster text output and
prints a clean Status/Method/Size/URL table. Each parser returns a list of
dicts with the same field shape, so downstream renderers don't care which
tool produced the input.
"""

from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path

# Feroxbuster's default output is colored; strip ANSI escape sequences before
# parsing so the regexes don't have to account for them.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Feroxbuster default text line:
#   "        200      GET        4l       46w      1234c http://t/admin"
# or with a redirect:
#   "        301      GET        0l        0w        0c http://t/login => /login/"
_FEROX_TEXT_RE = re.compile(
    r"^\s*(?P<status>\d{3})\s+"
    r"(?P<method>[A-Z]+)\s+"
    r"(?P<lines>\d+)l\s+"
    r"(?P<words>\d+)w\s+"
    r"(?P<size>\d+)c\s+"
    r"(?P<url>\S+)"
    r"(?:\s*=>\s*(?P<redirect>\S+))?\s*$"
)

# Gobuster dir-mode output:
#   "/admin                (Status: 200) [Size: 1234]"
#   "/login                (Status: 302) [Size: 0] [--> /login/]"
_GOBUSTER_RE = re.compile(
    r"^\s*(?P<path>\S+)\s+"
    r"\(Status:\s*(?P<status>\d+)\)\s+"
    r"\[Size:\s*(?P<size>\d+)\]"
    r"(?:\s+\[--> (?P<redirect>[^\]]+)\])?\s*$"
)


class WebFormat(str, Enum):
    AUTO = "auto"
    FEROXBUSTER = "feroxbuster"
    FEROXBUSTER_JSON = "feroxbuster-json"
    GOBUSTER = "gobuster"


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def parse_feroxbuster_text(path: Path) -> list[dict[str, str]]:
    """Parse feroxbuster default text output (one finding per line)."""
    results: list[dict[str, str]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _FEROX_TEXT_RE.match(_strip_ansi(raw))
        if match is None:
            continue
        results.append(
            {
                "status": match.group("status"),
                "method": match.group("method"),
                "size": match.group("size"),
                "words": match.group("words"),
                "lines": match.group("lines"),
                "url": match.group("url"),
                "redirect": match.group("redirect") or "-",
            }
        )
    return results


def parse_feroxbuster_json(path: Path) -> list[dict[str, str]]:
    """Parse feroxbuster `--json` output (newline-delimited JSON).

    Feroxbuster writes config/scan-start/report objects alongside the response
    rows we want; this filters to `"type": "response"` entries.
    """
    results: list[dict[str, str]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw or not raw.startswith("{"):
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if obj.get("type") != "response":
            continue
        results.append(
            {
                "status": str(obj.get("status", "-")),
                "method": str(obj.get("method", "GET")),
                "size": str(obj.get("content_length", "-")),
                "words": str(obj.get("word_count", "-")),
                "lines": str(obj.get("line_count", "-")),
                "url": str(obj.get("url", "-")),
                "redirect": "-",  # feroxbuster JSON doesn't carry redirect target inline
            }
        )
    return results


def parse_gobuster_text(path: Path) -> list[dict[str, str]]:
    """Parse gobuster dir-mode text output. gobuster doesn't report words/lines."""
    results: list[dict[str, str]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = _strip_ansi(raw).rstrip()
        if not line or line.startswith("="):
            continue
        match = _GOBUSTER_RE.match(line)
        if match is None:
            continue
        results.append(
            {
                "status": match.group("status"),
                "method": "GET",  # gobuster dir mode is always GET
                "size": match.group("size"),
                "words": "-",
                "lines": "-",
                "url": match.group("path"),
                "redirect": (match.group("redirect") or "-").strip(),
            }
        )
    return results


def detect_format(path: Path) -> WebFormat:
    """Sniff the file content to guess the format.

    Priority order: JSON (any line starts with `{` and parses) → gobuster
    (matches the `path (Status: N) [Size: N]` shape) → feroxbuster text.
    Falls back to feroxbuster text when nothing matches.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    nonblank = [_strip_ansi(line) for line in text.splitlines() if line.strip()]
    if not nonblank:
        return WebFormat.FEROXBUSTER  # empty file - any parser will yield []

    first = nonblank[0].strip()
    if first.startswith("{"):
        try:
            json.loads(first)
            return WebFormat.FEROXBUSTER_JSON
        except json.JSONDecodeError:
            pass

    for line in nonblank[:50]:
        if _GOBUSTER_RE.match(line):
            return WebFormat.GOBUSTER
        if _FEROX_TEXT_RE.match(line):
            return WebFormat.FEROXBUSTER

    return WebFormat.FEROXBUSTER


def parse_web_results(path: Path, fmt: WebFormat) -> list[dict[str, str]]:
    """Dispatch to the right parser; resolve AUTO via detect_format()."""
    if fmt is WebFormat.AUTO:
        fmt = detect_format(path)
    if fmt is WebFormat.FEROXBUSTER:
        return parse_feroxbuster_text(path)
    if fmt is WebFormat.FEROXBUSTER_JSON:
        return parse_feroxbuster_json(path)
    if fmt is WebFormat.GOBUSTER:
        return parse_gobuster_text(path)
    raise ValueError(f"Unsupported web format: {fmt!r}")


def filter_by_status(
    rows: list[dict[str, str]], statuses: list[str] | None
) -> list[dict[str, str]]:
    """Keep only rows whose `status` is in the allowed set; pass-through if None."""
    if not statuses:
        return rows
    allowed = {s.strip() for s in statuses}
    return [row for row in rows if row.get("status") in allowed]


def format_web_results(rows: list[dict[str, str]]) -> str:
    """Render a normalized result list as a fixed-width table.

    Redirect target (when present) is inlined into the URL column as
    `original -> target` so the table stays compact.
    """
    if not rows:
        return "No results found."

    headers = ["Status", "Method", "Size", "Words", "Lines", "URL"]
    body: list[list[str]] = []
    for row in rows:
        url = row["url"]
        if row.get("redirect", "-") != "-":
            url = f"{url} -> {row['redirect']}"
        body.append(
            [
                row["status"],
                row["method"],
                row["size"],
                row["words"],
                row["lines"],
                url,
            ]
        )

    widths = [
        max(len(r[i]) for r in [headers, *body]) for i in range(len(headers))
    ]

    def render_row(r: list[str]) -> str:
        return "  ".join(r[i].ljust(widths[i]) for i in range(len(r)))

    separator = "  ".join("-" * w for w in widths)
    return "\n".join([render_row(headers), separator, *(render_row(r) for r in body)])


def merge_web_results(
    files: list[tuple[Path, list[dict[str, str]]]],
) -> list[dict[str, str]]:
    """Dedupe rows across multiple parsed files, keyed by (method, status, url).

    The input is `(source_file, parsed_rows)` ordered oldest-first by mtime -
    matching the contract of `find_all_web_files`. When the same URL+method+
    status appears in more than one file, the most recent non-placeholder
    `size` / `words` / `lines` / `redirect` win, so a later targeted scan can
    refine an earlier broad one without losing data.

    Output rows are sorted by URL for stable display.
    """
    merged: dict[tuple[str, str, str], dict[str, str]] = {}
    for _path, rows in files:
        for row in rows:
            key = (row["method"], row["status"], row["url"])
            existing = merged.get(key)
            if existing is None:
                merged[key] = dict(row)
                continue
            for field_name in ("size", "words", "lines", "redirect"):
                value = row.get(field_name, "-")
                if value and value != "-":
                    existing[field_name] = value
    return sorted(merged.values(), key=lambda r: r["url"])
