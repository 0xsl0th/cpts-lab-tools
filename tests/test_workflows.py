from cpts_tools.services import _NAME_MAP, _PORT_MAP
from cpts_tools.workflows import all_ids, lookup, resolve


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
