from enum import Enum
from pathlib import Path
from typing import Annotated
from xml.etree import ElementTree

import typer

from . import __version__
from .findings import (
    Severity,
    add_finding,
    format_findings_table,
    list_findings,
)
from .nmap import (
    merge_scan_results,
    parse_nmap_grepable,
    parse_nmap_normal,
    parse_nmap_services,
)
from .render import (
    TargetContext,
    render_json,
    render_methodology,
    render_obsidian_vault,
    render_workflow,
)
from .report import check_report, format_report_check
from .services import canonicalize, ports_for
from .status import format_status, gather_status
from .workflows import all_ids as all_workflow_ids
from .workflows import lookup as lookup_workflow
from .workflows import resolve as resolve_workflows
from .workspace import (
    find_all_scans,
    find_latest_scan,
    init_workspace,
    read_metadata,
)

app = typer.Typer(
    help="Minimal helpers for authorized penetration-testing lab organization and reporting."
)
workspace_app = typer.Typer(
    help="Manage lab workspaces (folders, metadata, scan-driven methodology)."
)
finding_app = typer.Typer(
    help="Record and list engagement findings inside a workspace's report.md."
)
workflow_app = typer.Typer(
    help="Inspect the service workflow registry — list available workflows and "
    "print one to stdout without needing a workspace or a scan."
)
app.add_typer(workspace_app, name="workspace")
app.add_typer(finding_app, name="finding")
app.add_typer(workflow_app, name="workflow")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"reconlab {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the reconlab version and exit.",
            is_eager=True,
            callback=_version_callback,
        ),
    ] = False,
) -> None:
    """Minimal helpers for authorized penetration-testing lab organization and reporting."""


class InputFormat(str, Enum):
    AUTO = "auto"
    XML = "xml"
    NORMAL = "normal"
    GREPABLE = "grepable"


class OutputFormat(str, Enum):
    MD = "md"
    OBSIDIAN = "obsidian"
    JSON = "json"


_SUFFIX_TO_FORMAT: dict[str, InputFormat] = {
    ".xml": InputFormat.XML,
    ".nmap": InputFormat.NORMAL,
    ".gnmap": InputFormat.GREPABLE,
}


def _resolve_input(path: Path, fmt: InputFormat) -> tuple[Path, InputFormat]:
    """Resolve an `-i` path + format to a concrete (file, format) pair.

    Supports an `nmap -oA basename` style path that points at a sibling .xml /
    .nmap / .gnmap file. When format is AUTO, infers from extension or probes
    the basename in xml → normal → grepable priority.
    """
    if fmt is InputFormat.AUTO:
        if path.is_file():
            inferred = _SUFFIX_TO_FORMAT.get(path.suffix.lower())
            if inferred is None:
                raise typer.BadParameter(
                    f"Cannot infer input format from suffix '{path.suffix}'. "
                    "Pass --input-format explicitly (xml, normal, grepable)."
                )
            return path, inferred

        probed: list[Path] = []
        for ext, resolved in (
            (".xml", InputFormat.XML),
            (".nmap", InputFormat.NORMAL),
            (".gnmap", InputFormat.GREPABLE),
        ):
            candidate = path.parent / f"{path.name}{ext}"
            probed.append(candidate)
            if candidate.is_file():
                return candidate, resolved
        attempts = ", ".join(str(c) for c in probed)
        raise typer.BadParameter(
            f"No scan file found at '{path}' or as an -oA basename "
            f"(tried: {attempts})."
        )

    if not path.is_file():
        raise typer.BadParameter(f"Scan file not found: {path}")
    return path, fmt


def _parse_scan(path: Path, fmt: InputFormat) -> list[dict[str, str]]:
    if fmt is InputFormat.XML:
        return parse_nmap_services(path)
    if fmt is InputFormat.NORMAL:
        return parse_nmap_normal(path)
    if fmt is InputFormat.GREPABLE:
        return parse_nmap_grepable(path)
    raise typer.BadParameter(f"Unsupported input format: {fmt.value}")


def _render_suggest_from_services(
    services: list[dict[str, str]],
    *,
    target: str | None,
    host: str | None,
    domain: str | None,
    output_format: OutputFormat,
    output: Path | None,
    force: bool,
) -> None:
    """Render+write methodology from pre-parsed services. Single source of truth."""
    if output_format is OutputFormat.OBSIDIAN and output is None:
        raise typer.BadParameter(
            "--output-format obsidian requires -o / --output pointing to a vault directory."
        )

    target_ip = target or (services[0]["host"] if services else None)
    if not target_ip or target_ip == "-":
        raise typer.BadParameter(
            "Could not determine target IP from the scan — pass --target/-t explicitly."
        )

    detected: list[dict[str, str]] = []
    unmapped: list[dict[str, str]] = []
    canonical_ids: list[str] = []

    for svc in services:
        sid = canonicalize(svc["service"], svc["port"], svc["proto"])
        detected.append(svc)
        if sid:
            canonical_ids.append(sid)
        else:
            unmapped.append(svc)

    workflows = resolve_workflows(canonical_ids)
    context = TargetContext(
        target_ip=target_ip,
        target_host=host,
        domain=domain,
        detected=tuple(detected),
        unmapped=tuple(unmapped),
    )

    if output_format is OutputFormat.OBSIDIAN:
        assert output is not None  # guarded above
        files = render_obsidian_vault(context, workflows)
        output.mkdir(parents=True, exist_ok=True)
        existing = [output / rel for rel in files if (output / rel).exists()]
        if existing and not force:
            joined = "\n  ".join(str(p) for p in existing)
            raise typer.BadParameter(
                "Vault files already exist (pass --force to overwrite):\n  " + joined
            )
        for rel, content in files.items():
            target_path = output / rel
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(content, encoding="utf-8")
        typer.echo(f"Wrote Obsidian vault to {output} ({len(files)} files)")
        return

    # Single-document formats: md and json.
    if output_format is OutputFormat.JSON:
        rendered = render_json(context, workflows)
        label = "methodology JSON"
    else:
        rendered = render_methodology(context, workflows)
        label = "methodology"

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        typer.echo(f"Wrote {label} to {output}")
    else:
        typer.echo(rendered)


def _run_suggest(
    *,
    input_file: Path,
    input_format: InputFormat,
    target: str | None,
    host: str | None,
    domain: str | None,
    output_format: OutputFormat,
    output: Path | None,
    force: bool,
) -> None:
    """Body for `suggest-next` (single-scan entry point)."""
    resolved_path, resolved_format = _resolve_input(input_file, input_format)
    try:
        services = _parse_scan(resolved_path, resolved_format)
    except ElementTree.ParseError as exc:
        raise typer.BadParameter(f"Invalid nmap XML: {exc}") from exc
    _render_suggest_from_services(
        services,
        target=target,
        host=host,
        domain=domain,
        output_format=output_format,
        output=output,
        force=force,
    )


def format_services(services: list[dict[str, str]]) -> str:
    if not services:
        return "No open services found."

    headers = ["Host", "Names", "Port", "Proto", "Service", "Product", "Version"]
    rows = [
        [
            service["host"],
            service["hostnames"],
            service["port"],
            service["proto"],
            service["service"],
            service["product"],
            service["version"],
        ]
        for service in services
    ]
    widths = [
        max(len(str(row[index])) for row in [headers, *rows])
        for index in range(len(headers))
    ]

    def render_row(row: list[str]) -> str:
        return "  ".join(value.ljust(widths[index]) for index, value in enumerate(row))

    separator = "  ".join("-" * width for width in widths)
    return "\n".join([render_row(headers), separator, *(render_row(row) for row in rows)])


@app.command("parse-nmap")
def parse_nmap(
    xml_file: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Path to an nmap XML output file.",
        ),
    ],
) -> None:
    """Parse an nmap XML file and print a clean open-service summary."""
    try:
        typer.echo(format_services(parse_nmap_services(xml_file)))
    except ElementTree.ParseError as exc:
        raise typer.BadParameter(f"Invalid nmap XML: {exc}") from exc


@app.command("make-hosts")
def make_hosts(
    args: Annotated[
        list[str] | None,
        typer.Argument(
            metavar="[IP] [HOSTNAMES...]",
            help=(
                "Positional form: target IP followed by one or more hostnames. "
                "When --ip is also passed, these positionals are treated as additional "
                "hostnames (so `--aliases a b c` works naturally)."
            ),
        ),
    ] = None,
    ip: Annotated[
        str | None,
        typer.Option("--ip", help="Target IP address (flag form)."),
    ] = None,
    host: Annotated[
        str | None,
        typer.Option("--host", help="Primary hostname (flag form)."),
    ] = None,
    aliases: Annotated[
        list[str] | None,
        typer.Option(
            "--aliases",
            help=(
                "Hostname alias. May be repeated, or followed by additional "
                "space-separated hostnames as trailing positional arguments."
            ),
        ),
    ] = None,
) -> None:
    """Print the /etc/hosts entry plus the equivalent shell command. Does not modify any file."""
    positional = list(args or [])
    extra_aliases = list(aliases or [])

    if ip is not None:
        target_ip = ip
        hostnames: list[str] = []
        if host is not None:
            hostnames.append(host)
        hostnames.extend(extra_aliases)
        hostnames.extend(positional)
    else:
        if host is not None or extra_aliases:
            raise typer.BadParameter(
                "--host and --aliases require --ip. "
                "Either pass --ip too, or use the positional form `IP HOSTNAMES...`."
            )
        if not positional:
            raise typer.BadParameter(
                "Provide an IP and at least one hostname, "
                "e.g. `make-hosts 10.10.10.5 app.corp.local` or `--ip ... --host ...`."
            )
        if len(positional) < 2:
            raise typer.BadParameter(
                "Positional form needs IP plus at least one hostname."
            )
        target_ip = positional[0]
        hostnames = positional[1:]

    if not hostnames:
        raise typer.BadParameter(
            "At least one hostname is required (pass --host or trailing positional)."
        )

    line = f"{target_ip} {' '.join(hostnames)}"
    typer.echo("# Add this to /etc/hosts:")
    typer.echo(line)
    typer.echo("")
    typer.echo("# Or run:")
    typer.echo(f'echo "{line}" | sudo tee -a /etc/hosts')


def _warn_deprecated(command: str, replacement: str) -> None:
    """Emit a deprecation notice to stderr, keeping stdout output clean."""
    typer.echo(
        f"warning: `{command}` is deprecated and will be removed in a future "
        f"release; use {replacement} instead.",
        err=True,
    )


@app.command("report-init")
def report_init(
    machine: Annotated[str, typer.Argument(help="Machine name for the report folder.")],
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir",
            "-o",
            file_okay=False,
            dir_okay=True,
            help="Directory where the machine folder will be created.",
        ),
    ] = Path("."),
) -> None:
    """[DEPRECATED] Create a machine report folder structure. Use `workspace init` instead."""
    _warn_deprecated("report-init", "`workspace init`")
    machine_dir = output_dir / machine
    for folder in ("scans", "screenshots", "loot", "notes"):
        (machine_dir / folder).mkdir(parents=True, exist_ok=True)

    report_path = machine_dir / "report.md"
    if not report_path.exists():
        report_path.write_text(
            f"# {machine}\n\n"
            "## Summary\n\n"
            "## Scope\n\n"
            "- Authorized penetration-testing lab target only.\n\n"
            "## Enumeration\n\n"
            "## Findings\n\n"
            "## Lessons Learned\n",
            encoding="utf-8",
        )

    typer.echo(f"Created lab report structure at {machine_dir}")


@app.command("obsidian-note")
def obsidian_note(
    machine: Annotated[str, typer.Argument(help="Machine name for the note.")],
    target_ip: Annotated[
        str | None,
        typer.Option("--ip", help="Optional authorized lab target IP."),
    ] = None,
) -> None:
    """[DEPRECATED] Generate a Markdown machine note template. Use `workspace init` + `workspace suggest` instead."""
    _warn_deprecated("obsidian-note", "`workspace init` + `workspace suggest`")
    ip_value = target_ip or "TBD"
    typer.echo(
        f"# {machine}\n\n"
        "## Metadata\n\n"
        f"- Target IP: {ip_value}\n"
        "- Platform: Lab\n"
        "- Status: In progress\n"
        "- Scope: Authorized lab target only\n\n"
        "## Hostnames\n\n"
        "```text\n"
        f"{ip_value} {machine.lower()}.corp.local\n"
        "```\n\n"
        "## Enumeration\n\n"
        "### Nmap\n\n"
        "```bash\n"
        f"nmap -sV -sC -oA scans/{machine.lower()} {ip_value}\n"
        "```\n\n"
        "## Notes\n\n"
        "## Findings\n\n"
        "## Evidence\n\n"
        "## Lessons Learned\n"
    )


@app.command("suggest-next")
def suggest_next(
    input_file: Annotated[
        Path,
        typer.Option(
            "--input",
            "-i",
            file_okay=True,
            dir_okay=False,
            help=(
                "Path to a scan file (.xml / .nmap / .gnmap), or an `nmap -oA` "
                "basename like `scans/target`."
            ),
        ),
    ],
    input_format: Annotated[
        InputFormat,
        typer.Option(
            "--input-format",
            help=(
                "Scan file format. `auto` infers from extension or probes -oA "
                "basenames in xml → normal → grepable order."
            ),
        ),
    ] = InputFormat.AUTO,
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            "-t",
            help="Target IP for [TARGET_IP] placeholders. Defaults to the first host in the scan.",
        ),
    ] = None,
    host: Annotated[
        str | None,
        typer.Option("--host", help="Optional hostname for [TARGET_HOST] placeholders."),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", help="Optional domain for [DOMAIN] placeholders."),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--output-format",
            help=(
                "Output format. `md` writes a single Markdown file; `json` "
                "writes a structured JSON document; `obsidian` writes a vault "
                "folder (index, per-service notes, optional unmapped note)."
            ),
        ),
    ] = OutputFormat.MD,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help=(
                "For `md` and `json`: write the rendered document to this file "
                "(stdout if omitted). For `obsidian`: required, a vault "
                "directory to populate."
            ),
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help=(
                "Overwrite existing files in the Obsidian vault directory. "
                "Ignored for `--output-format md`."
            ),
        ),
    ] = False,
) -> None:
    """Generate service-based methodology guidance from an nmap scan."""
    _run_suggest(
        input_file=input_file,
        input_format=input_format,
        target=target,
        host=host,
        domain=domain,
        output_format=output_format,
        output=output,
        force=force,
    )


@workspace_app.command("init")
def workspace_init(
    name: Annotated[str, typer.Argument(help="Workspace name (used for the folder).")],
    target_ip: Annotated[
        str | None,
        typer.Option("--ip", help="Authorized lab target IP."),
    ] = None,
    target_host: Annotated[
        str | None,
        typer.Option("--host", help="Authorized lab target hostname."),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option("--domain", help="Domain for [DOMAIN] placeholders (often equals --host)."),
    ] = None,
    platform: Annotated[
        str,
        typer.Option("--platform", help="Free-form lab platform tag (e.g. lab, ctf, client)."),
    ] = "lab",
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir",
            "-o",
            file_okay=False,
            dir_okay=True,
            help="Parent directory where the workspace folder is created.",
        ),
    ] = Path("."),
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite an existing workspace at the same path."),
    ] = False,
) -> None:
    """Scaffold a lab workspace with folders, metadata, and a richer report scaffold."""
    workspace = output_dir / name
    try:
        metadata = init_workspace(
            workspace,
            name=name,
            target_ip=target_ip,
            target_host=target_host,
            domain=domain,
            platform=platform,
            force=force,
        )
    except FileExistsError as exc:
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(f"Initialized workspace at {workspace}")
    if metadata.target_ip:
        typer.echo(f"  Target IP: {metadata.target_ip}")
    if metadata.target_host:
        typer.echo(f"  Target host: {metadata.target_host}")
    if metadata.domain:
        typer.echo(f"  Domain: {metadata.domain}")
    typer.echo(f"  Platform: {metadata.platform}")
    typer.echo("Next: drop an nmap scan into scans/, then run `reconlab workspace suggest`.")


@workspace_app.command("suggest")
def workspace_suggest(
    path: Annotated[
        Path,
        typer.Argument(help="Workspace path (defaults to the current directory)."),
    ] = Path("."),
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--output-format",
            help=(
                "Methodology output format. Default `obsidian` writes a vault "
                "under notes/methodology/; `md` writes notes/methodology.md; "
                "`json` writes notes/methodology.json."
            ),
        ),
    ] = OutputFormat.OBSIDIAN,
    latest: Annotated[
        bool,
        typer.Option(
            "--latest",
            help=(
                "Use only the most recent scan in scans/. Default is to merge "
                "every .xml/.nmap/.gnmap file so multi-scan engagements (TCP + "
                "UDP + targeted rescan) see the full picture."
            ),
        ),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite existing methodology output."),
    ] = False,
) -> None:
    """Generate methodology for a workspace from its scans/ folder."""
    try:
        metadata = read_metadata(path)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc)) from exc

    scans_dir = path / "scans"

    if latest:
        single = find_latest_scan(scans_dir)
        if single is None:
            raise typer.BadParameter(
                f"No scan file (.xml / .nmap / .gnmap) in {scans_dir}. "
                "Drop an nmap output there first."
            )
        scan_paths: list[Path] = [single]
    else:
        scan_paths = find_all_scans(scans_dir)
        if not scan_paths:
            raise typer.BadParameter(
                f"No scan file (.xml / .nmap / .gnmap) in {scans_dir}. "
                "Drop an nmap output there first."
            )

    if len(scan_paths) == 1:
        typer.echo(f"Using scan: {scan_paths[0]}")
    else:
        typer.echo(f"Merging {len(scan_paths)} scans (oldest → newest):")
        for scan_path in scan_paths:
            typer.echo(f"  {scan_path}")

    parsed_scans: list[tuple[Path, list[dict[str, str]]]] = []
    for scan_path in scan_paths:
        fmt = _SUFFIX_TO_FORMAT.get(scan_path.suffix.lower())
        if fmt is None:
            typer.echo(f"  (skipping {scan_path.name}: unknown scan suffix)")
            continue
        try:
            parsed_scans.append((scan_path, _parse_scan(scan_path, fmt)))
        except ElementTree.ParseError as exc:
            raise typer.BadParameter(f"Invalid nmap XML in {scan_path}: {exc}") from exc

    if not parsed_scans:
        raise typer.BadParameter(
            f"No parseable scan files in {scans_dir}."
        )

    if len(parsed_scans) == 1:
        services = parsed_scans[0][1]
    else:
        services = merge_scan_results(parsed_scans)

    if output_format is OutputFormat.OBSIDIAN:
        output_path: Path = path / "notes" / "methodology"
    elif output_format is OutputFormat.JSON:
        output_path = path / "notes" / "methodology.json"
    else:
        output_path = path / "notes" / "methodology.md"

    _render_suggest_from_services(
        services,
        target=metadata.target_ip,
        host=metadata.target_host,
        domain=metadata.domain,
        output_format=output_format,
        output=output_path,
        force=force,
    )


@workspace_app.command("status")
def workspace_status(
    path: Annotated[
        Path,
        typer.Argument(help="Workspace path (defaults to the current directory)."),
    ] = Path("."),
) -> None:
    """Summarize a workspace's progress and the suggested next step."""
    try:
        status = gather_status(path)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(format_status(status))


@workspace_app.command("check")
def workspace_check(
    path: Annotated[
        Path,
        typer.Argument(help="Workspace path (defaults to the current directory)."),
    ] = Path("."),
) -> None:
    """Check a workspace report.md for wrap-up readiness (exits non-zero on issues)."""
    try:
        check = check_report(path)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(format_report_check(check))
    if not check.ok:
        raise typer.Exit(code=1)


@finding_app.command("add")
def finding_add(
    title: Annotated[
        str,
        typer.Option("--title", help="Short finding title."),
    ],
    severity: Annotated[
        Severity,
        typer.Option(
            "--severity",
            case_sensitive=False,
            help="Severity classification.",
        ),
    ],
    service: Annotated[
        str | None,
        typer.Option(
            "--service",
            help=(
                "Canonical service ID (e.g. smb, http). If it matches a workflow, "
                "the workflow report-note seeds the Description and a Methodology "
                "wikilink is added."
            ),
        ),
    ] = None,
    port: Annotated[
        str | None,
        typer.Option("--port", help="Affected port."),
    ] = None,
    description: Annotated[
        str | None,
        typer.Option(
            "--description",
            help="Description text. Overrides the workflow report-note seed.",
        ),
    ] = None,
    evidence: Annotated[
        list[str] | None,
        typer.Option(
            "--evidence",
            help=(
                "Path to evidence (screenshot, dump, etc). Repeat the flag to "
                "attach multiple files: `--evidence a.png --evidence b.png`."
            ),
        ),
    ] = None,
    workspace: Annotated[
        Path,
        typer.Argument(help="Workspace path (defaults to the current directory)."),
    ] = Path("."),
) -> None:
    """Append a structured finding to the workspace report.md."""
    try:
        number = add_finding(
            workspace,
            title=title,
            severity=severity,
            service=service,
            port=port,
            description=description,
            evidence=evidence,
        )
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(
        f"Recorded Finding {number} — {title} ({severity.display}) "
        f"in {workspace / 'report.md'}"
    )


@finding_app.command("list")
def finding_list(
    workspace: Annotated[
        Path,
        typer.Argument(help="Workspace path (defaults to the current directory)."),
    ] = Path("."),
) -> None:
    """Print the findings currently recorded in the workspace report.md."""
    try:
        findings = list_findings(workspace)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc)) from exc

    typer.echo(format_findings_table(findings))


_CATEGORY_ORDER: dict[str, int] = {
    "service-enum": 0,
    "post-foothold": 1,
    "lateral-movement": 2,
}


def _format_workflow_table() -> str:
    headers = ["Category", "ID", "Display", "Priority", "Ports"]
    rows: list[list[str]] = []
    for service_id in all_workflow_ids():
        workflow = lookup_workflow(service_id)
        if workflow is None:
            continue
        port_list = ports_for(service_id)
        ports_str = (
            ", ".join(f"{port}/{proto}" for port, proto in port_list)
            if port_list
            else "-"
        )
        rows.append(
            [
                workflow.category,
                service_id,
                workflow.display_name,
                str(workflow.priority),
                ports_str,
            ]
        )
    rows.sort(
        key=lambda r: (_CATEGORY_ORDER.get(r[0], 99), int(r[3]), r[1])
    )

    widths = [
        max(len(row[i]) for row in [headers, *rows]) for i in range(len(headers))
    ]

    def render_row(row: list[str]) -> str:
        return "  ".join(value.ljust(widths[i]) for i, value in enumerate(row))

    separator = "  ".join("-" * w for w in widths)
    return "\n".join([render_row(headers), separator, *(render_row(row) for row in rows)])


@workflow_app.command("list")
def workflow_list() -> None:
    """List every service workflow the tool knows about."""
    typer.echo(_format_workflow_table())


@workflow_app.command("show")
def workflow_show(
    service: Annotated[
        str,
        typer.Argument(
            help=(
                "Canonical service ID (e.g. smb, http, ldap). "
                "Run `reconlab workflow list` to see all available IDs."
            ),
        ),
    ],
    ip: Annotated[
        str | None,
        typer.Option(
            "--ip",
            help="Substitute [TARGET_IP] placeholders with this value.",
        ),
    ] = None,
    host: Annotated[
        str | None,
        typer.Option(
            "--host",
            help="Substitute [TARGET_HOST] placeholders with this value.",
        ),
    ] = None,
    domain: Annotated[
        str | None,
        typer.Option(
            "--domain",
            help="Substitute [DOMAIN] placeholders with this value.",
        ),
    ] = None,
) -> None:
    """Print one service workflow as Markdown — no workspace or scan required."""
    workflow = lookup_workflow(service)
    if workflow is None:
        known = ", ".join(sorted(all_workflow_ids()))
        raise typer.BadParameter(
            f"Unknown service workflow '{service}'. Known IDs: {known}."
        )

    context = TargetContext(
        target_ip=ip or "[TARGET_IP]",
        target_host=host,
        domain=domain,
        detected=(),
        unmapped=(),
    )
    typer.echo("\n".join(render_workflow(workflow, context)))


if __name__ == "__main__":
    app()
