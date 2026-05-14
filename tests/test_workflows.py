from cpts_tools.services import _NAME_MAP, _PORT_MAP
from cpts_tools.workflows import all_ids, by_category, lookup, resolve


def test_lookup_known_service_returns_workflow() -> None:
    workflow = lookup("smb")
    assert workflow is not None
    assert workflow.service_id == "smb"
    assert workflow.checklist
    assert workflow.commands
    assert workflow.troubleshooting


def test_lookup_unknown_service_returns_none() -> None:
    assert lookup("does-not-exist") is None


def test_resolve_dedupes_and_orders_by_priority() -> None:
    workflows = resolve(["ssh", "smb", "http", "smb", "ssh"])

    ids = [w.service_id for w in workflows]
    assert ids == ["smb", "http", "ssh"]


def test_resolve_skips_unknown_ids() -> None:
    workflows = resolve(["smb", "fictional-service"])
    assert [w.service_id for w in workflows] == ["smb"]


def test_every_canonical_service_id_has_a_workflow() -> None:
    canonical_ids = set(_NAME_MAP.keys()) | set(_PORT_MAP.keys())
    missing = canonical_ids - set(all_ids())
    assert not missing, f"Workflows missing for canonical services: {sorted(missing)}"


def test_priorities_keep_rce_class_ahead_of_info_class() -> None:
    smb = lookup("smb")
    ssh = lookup("ssh")
    assert smb is not None and ssh is not None
    assert smb.priority < ssh.priority


def test_every_workflow_has_display_name() -> None:
    for sid in all_ids():
        workflow = lookup(sid)
        assert workflow is not None
        assert workflow.display_name, f"Workflow {sid} missing display_name"


def test_every_related_id_references_a_known_workflow() -> None:
    known = set(all_ids())
    for sid in all_ids():
        workflow = lookup(sid)
        assert workflow is not None
        missing = [r for r in workflow.related if r not in known]
        assert not missing, f"Workflow {sid} references unknown: {missing}"


def test_service_workflows_default_to_service_enum_category() -> None:
    for sid in ("smb", "http", "ldap", "kerberos", "nfs"):
        workflow = lookup(sid)
        assert workflow is not None
        assert workflow.category == "service-enum"


def test_post_foothold_workflows_exist() -> None:
    for sid in ("linux-privesc", "windows-privesc", "ad-foothold"):
        workflow = lookup(sid)
        assert workflow is not None
        assert workflow.category == "post-foothold"
        assert workflow.checklist and workflow.commands and workflow.troubleshooting


def test_pivoting_is_lateral_movement() -> None:
    workflow = lookup("pivoting")
    assert workflow is not None
    assert workflow.category == "lateral-movement"


def test_by_category_returns_sorted_workflows() -> None:
    post = by_category("post-foothold")
    assert [w.service_id for w in post] == [
        "linux-privesc",
        "windows-privesc",
        "ad-foothold",
    ]
    lateral = by_category("lateral-movement")
    assert [w.service_id for w in lateral] == ["pivoting"]


def test_by_category_unknown_returns_empty() -> None:
    assert by_category("does-not-exist") == []


def test_post_foothold_workflows_are_not_canonical_services() -> None:
    # They must not be reachable via canonicalize / resolve from a scan.
    canonical = set(_NAME_MAP.keys()) | set(_PORT_MAP.keys())
    for sid in ("linux-privesc", "windows-privesc", "ad-foothold", "pivoting"):
        assert sid not in canonical


def test_post_foothold_workflows_use_lab_safe_placeholders() -> None:
    # No real IPs/hosts baked in — only the agreed placeholder tokens.
    for sid in ("linux-privesc", "windows-privesc", "ad-foothold", "pivoting"):
        workflow = lookup(sid)
        assert workflow is not None
        blob = " ".join(
            [
                workflow.when_to_use,
                *workflow.checklist,
                *(c for c, _ in workflow.commands),
                workflow.report_note,
            ]
        )
        # The blob may contain placeholders, never a 10.x style literal IP.
        assert "10.10.10." not in blob
        assert "10.129." not in blob
