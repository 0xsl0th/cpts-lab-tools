"""Render a methodology document (single Markdown file or Obsidian vault)."""

from dataclasses import dataclass

from .workflows import Workflow, by_category
from .workflows import lookup as lookup_workflow

_POST_FOOTHOLD_CATEGORIES = ("post-foothold", "lateral-movement")


@dataclass(frozen=True)
class TargetContext:
    target_ip: str
    target_host: str | None
    domain: str | None
    detected: tuple[dict[str, str], ...]
    unmapped: tuple[dict[str, str], ...]


def _apply_placeholders(text: str, context: TargetContext) -> str:
    replacements = {
        "[TARGET_IP]": context.target_ip,
        "[TARGET_HOST]": context.target_host or "[TARGET_HOST]",
        "[DOMAIN]": context.domain or "[DOMAIN]",
    }
    for key, value in replacements.items():
        text = text.replace(key, value)
    return text


def _escape_cell(text: str) -> str:
    return text.replace("|", "\\|")


def _detected_table(detected: tuple[dict[str, str], ...]) -> list[str]:
    if not detected:
        return ["_No open services detected in the scan._", ""]
    rows = [
        "| Port | Proto | Service | Product | Version |",
        "|------|-------|---------|---------|---------|",
    ]
    for svc in detected:
        rows.append(
            "| {port} | {proto} | {service} | {product} | {version} |".format(**svc)
        )
    rows.append("")
    return rows


def render_workflow(workflow: Workflow, context: TargetContext) -> list[str]:
    """Render one workflow as a list of Markdown lines.

    Public entry point used by `render_methodology` and by the
    `workflow show` CLI command.
    """
    lines: list[str] = [f"## {_apply_placeholders(workflow.title, context)}", ""]
    lines.append(f"**When to use:** {_apply_placeholders(workflow.when_to_use, context)}")
    lines.append("")

    lines.append("### Checklist")
    lines.append("")
    for item in workflow.checklist:
        lines.append(f"- [ ] {_apply_placeholders(item, context)}")
    lines.append("")

    lines.append("### Commands")
    lines.append("")
    lines.append("| Command | Expected outcome |")
    lines.append("|---------|------------------|")
    for cmd, outcome in workflow.commands:
        cmd_md = _escape_cell(_apply_placeholders(cmd, context))
        outcome_md = _escape_cell(_apply_placeholders(outcome, context))
        lines.append(f"| `{cmd_md}` | {outcome_md} |")
    lines.append("")

    lines.append("### Expected output")
    lines.append("")
    lines.append(_apply_placeholders(workflow.expected_output, context))
    lines.append("")

    lines.append("### Verification")
    lines.append("")
    for item in workflow.verification:
        lines.append(f"- [ ] {_apply_placeholders(item, context)}")
    lines.append("")

    lines.append("### Troubleshooting")
    lines.append("")
    lines.append("| Problem | Cause | Fix |")
    lines.append("|---------|-------|-----|")
    for problem, cause, fix in workflow.troubleshooting:
        lines.append(
            "| {p} | {c} | {f} |".format(
                p=_escape_cell(_apply_placeholders(problem, context)),
                c=_escape_cell(_apply_placeholders(cause, context)),
                f=_escape_cell(_apply_placeholders(fix, context)),
            )
        )
    lines.append("")

    lines.append("### Report note")
    lines.append("")
    lines.append(_apply_placeholders(workflow.report_note, context))
    lines.append("")
    return lines


def _after_foothold_lines() -> list[str]:
    """Footer pointing at post-foothold workflows reachable via `workflow show`."""
    followups: list[Workflow] = []
    for category in _POST_FOOTHOLD_CATEGORIES:
        followups.extend(by_category(category))
    if not followups:
        return []

    lines = [
        "## After a Foothold",
        "",
        "Service enumeration above gets you to initial access. Once you have a "
        "shell or a valid credential, continue with the post-foothold workflows "
        "(no scan required):",
        "",
    ]
    for workflow in followups:
        lines.append(
            f"- `cpts-tools workflow show {workflow.service_id}` — {workflow.title}"
        )
    lines.append("")
    return lines


def render_methodology(context: TargetContext, workflows: list[Workflow]) -> str:
    host_line = context.target_host or "[TARGET_HOST]"
    domain_line = context.domain or "[DOMAIN]"

    lines: list[str] = [f"# Methodology — {context.target_ip}", ""]

    lines.append("## Scope & Assumptions")
    lines.append("")
    lines.append(
        "- Authorized HTB/CPTS lab target only — do not run these commands against systems you are not explicitly permitted to test."
    )
    lines.append(f"- Target IP: `{context.target_ip}`")
    lines.append(f"- Target host: `{host_line}`")
    lines.append(f"- Domain: `{domain_line}`")
    lines.append(
        "- Placeholders such as `[USER]`, `[PASS]`, `[LHOST]`, `[LPORT]` are left for the operator to fill in per step."
    )
    lines.append("")

    lines.append("## Detected Services")
    lines.append("")
    lines.extend(_detected_table(context.detected))

    lines.append("## Prioritized Methodology")
    lines.append("")
    if workflows:
        lines.append("Work top-to-bottom; RCE-class services are ordered first.")
        lines.append("")
        for workflow in workflows:
            lines.extend(render_workflow(workflow, context))
    else:
        lines.append("_No workflow matched the detected services._")
        lines.append("")

    if context.unmapped:
        lines.append("## Unmapped Services")
        lines.append("")
        lines.append(
            "These open ports have no workflow yet. Enumerate manually and consider contributing a workflow back."
        )
        lines.append("")
        for svc in context.unmapped:
            label = (
                f"- `{svc['port']}/{svc['proto']}` — "
                f"{svc['service']} {svc['product']} {svc['version']}"
            ).rstrip()
            lines.append(label)
        lines.append("")

    lines.extend(_after_foothold_lines())

    lines.append("## Aggregated Report Note Draft")
    lines.append("")
    lines.append(
        f"During authorized testing of `{context.target_ip}` "
        f"(`{host_line}`, domain `{domain_line}`), the listed services were enumerated "
        "and the per-service methodology above was applied. Findings, evidence, and "
        "concrete recommendations should be recorded per section and rolled up into "
        "the engagement report."
    )
    lines.append("")
    return "\n".join(lines)


def _wikilink(workflow: Workflow) -> str:
    return f"[[services/{workflow.service_id}|{workflow.display_name}]]"


def _related_wikilinks(workflow: Workflow) -> list[str]:
    links: list[str] = []
    for related_id in workflow.related:
        related = lookup_workflow(related_id)
        if related is not None:
            links.append(_wikilink(related))
    return links


def _frontmatter(fields: list[tuple[str, str]], tags: list[str]) -> list[str]:
    lines = ["---"]
    for key, value in fields:
        lines.append(f"{key}: {value}")
    lines.append("tags:")
    for tag in tags:
        lines.append(f"  - {tag}")
    lines.append("---")
    lines.append("")
    return lines


def _render_service_note(workflow: Workflow, context: TargetContext) -> str:
    lines: list[str] = []
    lines.extend(
        _frontmatter(
            fields=[
                ("title", workflow.display_name),
                ("target", context.target_ip),
                ("service", workflow.service_id),
                ("priority", str(workflow.priority)),
                ("status", "in-progress"),
            ],
            tags=["methodology", workflow.service_id],
        )
    )
    lines.append(f"# {workflow.display_name}")
    lines.append("")
    lines.append(f"**When to use:** {_apply_placeholders(workflow.when_to_use, context)}")
    lines.append("")

    lines.append("## Checklist")
    lines.append("")
    for item in workflow.checklist:
        lines.append(f"- [ ] {_apply_placeholders(item, context)}")
    lines.append("")

    lines.append("## Commands")
    lines.append("")
    lines.append("| Command | Expected outcome |")
    lines.append("|---------|------------------|")
    for cmd, outcome in workflow.commands:
        cmd_md = _escape_cell(_apply_placeholders(cmd, context))
        outcome_md = _escape_cell(_apply_placeholders(outcome, context))
        lines.append(f"| `{cmd_md}` | {outcome_md} |")
    lines.append("")

    lines.append("## Expected output")
    lines.append("")
    lines.append(_apply_placeholders(workflow.expected_output, context))
    lines.append("")

    lines.append("## Verification")
    lines.append("")
    for item in workflow.verification:
        lines.append(f"- [ ] {_apply_placeholders(item, context)}")
    lines.append("")

    lines.append("## Troubleshooting")
    lines.append("")
    lines.append("| Problem | Cause | Fix |")
    lines.append("|---------|-------|-----|")
    for problem, cause, fix in workflow.troubleshooting:
        lines.append(
            "| {p} | {c} | {f} |".format(
                p=_escape_cell(_apply_placeholders(problem, context)),
                c=_escape_cell(_apply_placeholders(cause, context)),
                f=_escape_cell(_apply_placeholders(fix, context)),
            )
        )
    lines.append("")

    lines.append("## Report note")
    lines.append("")
    lines.append(_apply_placeholders(workflow.report_note, context))
    lines.append("")

    related_links = _related_wikilinks(workflow)
    if related_links:
        lines.append("## Related")
        lines.append("")
        for link in related_links:
            lines.append(f"- {link}")
        lines.append("")

    return "\n".join(lines)


def _render_index(context: TargetContext, workflows: list[Workflow], has_unmapped: bool) -> str:
    host_line = context.target_host or "[TARGET_HOST]"
    domain_line = context.domain or "[DOMAIN]"

    lines: list[str] = []
    lines.extend(
        _frontmatter(
            fields=[
                ("title", f"Methodology — {context.target_ip}"),
                ("target", context.target_ip),
                ("target_host", host_line),
                ("domain", domain_line),
                ("status", "in-progress"),
            ],
            tags=["methodology", "moc"],
        )
    )

    lines.append(f"# Methodology — {context.target_ip}")
    lines.append("")

    lines.append("## Scope & Assumptions")
    lines.append("")
    lines.append(
        "- Authorized HTB/CPTS lab target only — do not run these commands against systems you are not explicitly permitted to test."
    )
    lines.append(f"- Target IP: `{context.target_ip}`")
    lines.append(f"- Target host: `{host_line}`")
    lines.append(f"- Domain: `{domain_line}`")
    lines.append(
        "- Placeholders such as `[USER]`, `[PASS]`, `[LHOST]`, `[LPORT]` are left for the operator to fill in per step."
    )
    lines.append("")

    lines.append("## Detected Services")
    lines.append("")
    lines.extend(_detected_table(context.detected))

    lines.append("## Prioritized Methodology")
    lines.append("")
    if workflows:
        lines.append("Work top-to-bottom; RCE-class services are ordered first.")
        lines.append("")
        for index, workflow in enumerate(workflows, start=1):
            lines.append(f"{index}. {_wikilink(workflow)}")
        lines.append("")
    else:
        lines.append("_No workflow matched the detected services._")
        lines.append("")

    if has_unmapped:
        lines.append("## Unmapped Services")
        lines.append("")
        lines.append("See [[unmapped|Unmapped Services]] for open ports without a workflow.")
        lines.append("")

    lines.extend(_after_foothold_lines())

    lines.append("## Aggregated Report Note Draft")
    lines.append("")
    lines.append(
        f"During authorized testing of `{context.target_ip}` "
        f"(`{host_line}`, domain `{domain_line}`), the listed services were enumerated "
        "and the per-service methodology was applied. Findings, evidence, and concrete "
        "recommendations should be recorded in each service note and rolled up here."
    )
    lines.append("")

    return "\n".join(lines)


def _render_unmapped(context: TargetContext) -> str:
    lines: list[str] = []
    lines.extend(
        _frontmatter(
            fields=[
                ("title", "Unmapped Services"),
                ("target", context.target_ip),
                ("status", "in-progress"),
            ],
            tags=["methodology", "unmapped"],
        )
    )
    lines.append("# Unmapped Services")
    lines.append("")
    lines.append(
        "These open ports have no workflow yet. Enumerate manually and consider "
        "contributing a workflow back."
    )
    lines.append("")
    for svc in context.unmapped:
        label = (
            f"- `{svc['port']}/{svc['proto']}` — "
            f"{svc['service']} {svc['product']} {svc['version']}"
        ).rstrip()
        lines.append(label)
    lines.append("")
    return "\n".join(lines)


def render_obsidian_vault(
    context: TargetContext,
    workflows: list[Workflow],
) -> dict[str, str]:
    """Return relative-path -> file-content for an Obsidian vault layout."""
    files: dict[str, str] = {}
    files["index.md"] = _render_index(context, workflows, bool(context.unmapped))
    for workflow in workflows:
        files[f"services/{workflow.service_id}.md"] = _render_service_note(
            workflow, context
        )
    if context.unmapped:
        files["unmapped.md"] = _render_unmapped(context)
    return files
