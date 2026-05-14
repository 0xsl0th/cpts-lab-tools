from pathlib import Path
from typing import Annotated
from xml.etree import ElementTree

import typer

app = typer.Typer(
    help="Minimal helpers for authorized HTB/CPTS lab organization and reporting."
)


def _text(value: str | None, default: str = "-") -> str:
    if value is None or value.strip() == "":
        return default
    return value.strip()


def parse_nmap_services(xml_path: Path) -> list[dict[str, str]]:
    root = ElementTree.parse(xml_path).getroot()
    services: list[dict[str, str]] = []

    for host in root.findall("host"):
        address = host.find("address")
        host_ip = address.get("addr", "-") if address is not None else "-"
        hostname_nodes = host.findall("hostnames/hostname")
        hostnames = ", ".join(
            name
            for node in hostname_nodes
            if (name := node.get("name"))
        )

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            services.append(
                {
                    "host": host_ip,
                    "hostnames": hostnames or "-",
                    "port": port.get("portid", "-"),
                    "proto": port.get("protocol", "-"),
                    "service": _text(service.get("name") if service is not None else None),
                    "product": _text(service.get("product") if service is not None else None),
                    "version": _text(service.get("version") if service is not None else None),
                }
            )

    return services


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


if __name__ == "__main__":
    app()
