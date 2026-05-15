from cpts_tools.render import TargetContext, render_methodology
from cpts_tools.workflows import lookup, resolve


def _ctx(**overrides):
    base = dict(
        target_ip="10.10.10.5",
        target_host="target.corp.local",
        domain="target.corp.local",
        detected=(),
        unmapped=(),
    )
    base.update(overrides)
    return TargetContext(**base)


def test_render_includes_required_top_level_sections() -> None:
    context = _ctx()
    output = render_methodology(context, [])

    assert "# Methodology — 10.10.10.5" in output
    assert "## Scope & Assumptions" in output
    assert "## Detected Services" in output
    assert "## Prioritized Methodology" in output
    assert "## After a Foothold" in output
    assert "## Aggregated Report Note Draft" in output


def test_render_after_foothold_footer_points_at_post_foothold_workflows() -> None:
    output = render_methodology(_ctx(), [])

    assert "## After a Foothold" in output
    assert "cpts-tools workflow show linux-privesc" in output
    assert "cpts-tools workflow show windows-privesc" in output
    assert "cpts-tools workflow show ad-foothold" in output
    assert "cpts-tools workflow show pivoting" in output
    # The footer sits before the aggregated report note.
    assert output.index("## After a Foothold") < output.index(
        "## Aggregated Report Note Draft"
    )


def test_render_substitutes_known_placeholders() -> None:
    context = _ctx()
    workflows = resolve(["smb"])
    output = render_methodology(context, workflows)

    assert "[TARGET_IP]" not in output
    assert "[TARGET_HOST]" not in output
    assert "[DOMAIN]" not in output
    assert "10.10.10.5" in output
    assert "target.corp.local" in output


def test_render_leaves_operator_placeholders_untouched() -> None:
    context = _ctx()
    workflows = resolve(["smb"])
    output = render_methodology(context, workflows)

    assert "[USER]" in output
    assert "[PASS]" in output


def test_render_keeps_target_host_placeholder_when_host_is_missing() -> None:
    context = _ctx(target_host=None, domain=None)
    output = render_methodology(context, resolve(["https"]))

    assert "[TARGET_HOST]" in output
    assert "[DOMAIN]" in output


def test_render_emits_workflow_sections_in_priority_order() -> None:
    context = _ctx()
    workflows = resolve(["ssh", "smb"])
    output = render_methodology(context, workflows)

    smb_index = output.index("SMB (139/445)")
    ssh_index = output.index("SSH (22)")
    assert smb_index < ssh_index


def test_render_lists_detected_services_in_table() -> None:
    detected = (
        {
            "host": "10.10.10.5",
            "hostnames": "target.corp.local",
            "port": "445",
            "proto": "tcp",
            "service": "microsoft-ds",
            "product": "Samba",
            "version": "4.15.0",
        },
    )
    output = render_methodology(_ctx(detected=detected), resolve(["smb"]))

    assert "| Port | Proto | Service | Product | Version |" in output
    assert "| 445 | tcp | microsoft-ds | Samba | 4.15.0 |" in output


def test_render_surfaces_unmapped_services() -> None:
    unmapped = (
        {
            "host": "10.10.10.5",
            "hostnames": "-",
            "port": "9999",
            "proto": "tcp",
            "service": "abyss",
            "product": "-",
            "version": "-",
        },
    )
    output = render_methodology(_ctx(unmapped=unmapped), [])

    assert "## Unmapped Services" in output
    assert "9999/tcp" in output
    assert "abyss" in output


def test_render_handles_no_workflows() -> None:
    output = render_methodology(_ctx(), [])
    assert "_No workflow matched the detected services._" in output


def test_render_substitutes_placeholders_inside_workflow_body() -> None:
    smb = lookup("smb")
    assert smb is not None
    context = _ctx()
    output = render_methodology(context, [smb])

    assert "smbclient -N -L //10.10.10.5" in output
