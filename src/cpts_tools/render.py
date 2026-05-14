"""Render a methodology Markdown document from a target context and workflows."""

from dataclasses import dataclass

from .workflows import Workflow


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


def _render_workflow(workflow: Workflow, context: TargetContext) -> list[str]:
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
            lines.extend(_render_workflow(workflow, context))
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
