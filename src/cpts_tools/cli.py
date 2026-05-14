from enum import Enum
from pathlib import Path
from typing import Annotated
from xml.etree import ElementTree

import typer

from .nmap import (
    parse_nmap_grepable,
    parse_nmap_normal,
    parse_nmap_services,
)
from .render import TargetContext, render_methodology, render_obsidian_vault
from .services import canonicalize
from .workflows import resolve as resolve_workflows
from .workspace import (
    find_latest_scan,
    init_workspace,
    read_metadata,
)

app = typer.Typer(
    help="Minimal helpers for authorized HTB/CPTS lab organization and reporting."
)
workspace_app = typer.Typer(
    help="Manage lab workspaces (folders, metadata, scan-driven methodology)."
)
app.add_typer(workspace_app, name="workspace")


class InputFormat(str, Enum):
    AUTO = "auto"
    XML = "xml"
    NORMAL = "normal"
    GREPABLE = "grepable"


class OutputFormat(str, Enum):
    MD = "md"
    OBSIDIAN = "obsidian"


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
    """Shared body for `suggest-next` and `workspace suggest`.

    Resolves the scan file + format, parses services, canonicalizes them to workflow
    IDs, renders Markdown or an Obsidian vault, and writes to disk or stdout.
    """
    if output_format is OutputFormat.OBSIDIAN and output is None:
        raise typer.BadParameter(
            "--output-format obsidian requires -o / --output pointing to a vault directory."
        )

    resolved_path, resolved_format = _resolve_input(input_file, input_format)

    try:
        services = _parse_scan(resolved_path, resolved_format)
    except ElementTree.ParseError as exc:
        raise typer.BadParameter(f"Invalid nmap XML: {exc}") from exc

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

    if output_format is OutputFormat.MD:
        markdown = render_methodology(context, workflows)
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(markdown, encoding="utf-8")
            typer.echo(f"Wrote methodology to {output}")
        else:
            typer.echo(markdown)
        return

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
    target_ip: Annotated[str, typer.Argument(help="Target lab IP address.")],
    hostnames: Annotated[
        list[str],
        typer.Argument(help="One or more lab hostnames for the target."),
    ],
) -> None:
    """Print an /etc/hosts line for an authorized lab target."""
    typer.echo(f"{target_ip}\t{' '.join(hostnames)}")


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
    """Create a machine report folder structure."""
    machine_dir = output_dir / machine
    for folder in ("scans", "screenshots", "loot", "notes"):
        (machine_dir / folder).mkdir(parents=True, exist_ok=True)

    report_path = machine_dir / "report.md"
    if not report_path.exists():
        report_path.write_text(
            f"# {machine}\n\n"
            "## Summary\n\n"
            "## Scope\n\n"
            "- Authorized HTB/CPTS lab target only.\n\n"
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
    """Generate a Markdown machine note template."""
    ip_value = target_ip or "TBD"
    typer.echo(
        f"# {machine}\n\n"
        "## Metadata\n\n"
        f"- Target IP: {ip_value}\n"
        "- Platform: HTB/CPTS Lab\n"
        "- Status: In progress\n"
        "- Scope: Authorized lab target only\n\n"
        "## Hostnames\n\n"
        "```text\n"
        f"{ip_value} {machine.lower()}.htb\n"
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
                "Output format. `md` writes a single Markdown file; `obsidian` "
                "writes a vault folder (index, per-service notes, optional "
                "unmapped note)."
            ),
        ),
    ] = OutputFormat.MD,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help=(
                "For `md`: write the rendered methodology to this file (stdout "
                "if omitted). For `obsidian`: required, a vault directory to "
                "populate."
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
        typer.Option("--platform", help="Lab platform tag (htb, cpts, thm, other)."),
    ] = "htb",
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
    typer.echo("Next: drop an nmap scan into scans/, then run `cpts-tools workspace suggest`.")


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
                "Methodology output format. Default `obsidian` writes a vault under "
                "notes/methodology/; `md` writes a single notes/methodology.md."
            ),
        ),
    ] = OutputFormat.OBSIDIAN,
    force: Annotated[
        bool,
        typer.Option("--force", help="Overwrite existing methodology output."),
    ] = False,
) -> None:
    """Generate methodology for a workspace using its most recent scan."""
    try:
        metadata = read_metadata(path)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc)) from exc

    scans_dir = path / "scans"
    scan = find_latest_scan(scans_dir)
    if scan is None:
        raise typer.BadParameter(
            f"No scan file (.xml / .nmap / .gnmap) in {scans_dir}. "
            "Drop an nmap output there first."
        )

    if output_format is OutputFormat.OBSIDIAN:
        output_path: Path = path / "notes" / "methodology"
    else:
        output_path = path / "notes" / "methodology.md"

    typer.echo(f"Using scan: {scan}")
    _run_suggest(
        input_file=scan,
        input_format=InputFormat.AUTO,
        target=metadata.target_ip,
        host=metadata.target_host,
        domain=metadata.domain,
        output_format=output_format,
        output=output_path,
        force=force,
    )


if __name__ == "__main__":
    app()
