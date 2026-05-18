import json

from reconlab.render import TargetContext, render_json
from reconlab.workflows import resolve


def _ctx(**overrides):
    base = dict(
        target_ip="10.10.10.5",
        target_host="app.corp.local",
        domain="corp.local",
        detected=(),
        unmapped=(),
    )
    base.update(overrides)
    return TargetContext(**base)


def test_render_json_is_valid_json() -> None:
    data = json.loads(render_json(_ctx(), resolve(["smb"])))
    assert isinstance(data, dict)
    assert set(data) == {
        "target",
        "detected_services",
        "unmapped_services",
        "workflows",
        "after_foothold",
    }


def test_render_json_includes_target_block() -> None:
    data = json.loads(render_json(_ctx(), []))
    assert data["target"] == {
        "ip": "10.10.10.5",
        "host": "app.corp.local",
        "domain": "corp.local",
    }


def test_render_json_target_host_and_domain_null_when_missing() -> None:
    data = json.loads(render_json(_ctx(target_host=None, domain=None), []))
    assert data["target"]["host"] is None
    assert data["target"]["domain"] is None


def test_render_json_lists_detected_and_unmapped_services() -> None:
    detected = (
        {
            "host": "10.10.10.5",
            "hostnames": "app.corp.local",
            "port": "445",
            "proto": "tcp",
            "service": "microsoft-ds",
            "product": "Samba",
            "version": "4.15.0",
        },
    )
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
    data = json.loads(render_json(_ctx(detected=detected, unmapped=unmapped), []))
    assert data["detected_services"][0]["port"] == "445"
    assert data["detected_services"][0]["product"] == "Samba"
    assert data["unmapped_services"][0]["service"] == "abyss"


def test_render_json_workflow_is_fully_structured() -> None:
    data = json.loads(render_json(_ctx(), resolve(["smb"])))
    [smb] = data["workflows"]

    assert smb["service_id"] == "smb"
    assert smb["category"] == "service-enum"
    assert isinstance(smb["priority"], int)
    assert isinstance(smb["checklist"], list) and smb["checklist"]
    # Commands are {command, outcome} objects.
    assert set(smb["commands"][0]) == {"command", "outcome"}
    # Troubleshooting rows are {problem, cause, fix} objects.
    assert set(smb["troubleshooting"][0]) == {"problem", "cause", "fix"}
    assert smb["related"] == ["ldap", "kerberos"]


def test_render_json_substitutes_target_placeholders() -> None:
    rendered = render_json(_ctx(), resolve(["smb"]))
    assert "[TARGET_IP]" not in rendered
    assert "10.10.10.5" in rendered
    # Operator placeholders are preserved, as in the md/obsidian renderers.
    assert "[USER]" in rendered
    assert "[PASS]" in rendered


def test_render_json_keeps_target_host_placeholder_in_text_when_missing() -> None:
    # target.host is null, but workflow text keeps the literal [TARGET_HOST]
    # placeholder - consistent with render_methodology / render_obsidian_vault.
    rendered = render_json(_ctx(target_host=None, domain=None), resolve(["https"]))
    data = json.loads(rendered)
    assert data["target"]["host"] is None
    assert "[TARGET_HOST]" in rendered


def test_render_json_includes_after_foothold_refs() -> None:
    data = json.loads(render_json(_ctx(), resolve(["smb"])))
    ids = {entry["service_id"] for entry in data["after_foothold"]}
    assert {"linux-privesc", "windows-privesc", "ad-foothold", "pivoting"} <= ids
    # Post-foothold workflows are not mixed into the main workflow list.
    assert "linux-privesc" not in {w["service_id"] for w in data["workflows"]}


def test_render_json_no_workflows_yields_empty_list() -> None:
    data = json.loads(render_json(_ctx(), []))
    assert data["workflows"] == []
