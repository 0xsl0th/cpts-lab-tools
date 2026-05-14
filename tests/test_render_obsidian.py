from cpts_tools.render import TargetContext, render_obsidian_vault
from cpts_tools.workflows import lookup, resolve


def _ctx(**overrides):
    base = dict(
        target_ip="10.10.10.5",
        target_host="target.htb",
        domain="target.htb",
        detected=(),
        unmapped=(),
    )
    base.update(overrides)
    return TargetContext(**base)


def test_vault_contains_index_and_per_service_notes() -> None:
    workflows = resolve(["smb", "http", "rdp"])
    vault = render_obsidian_vault(_ctx(), workflows)

    assert set(vault) == {
        "index.md",
        "services/smb.md",
        "services/http.md",
        "services/rdp.md",
    }


def test_vault_omits_unmapped_file_when_no_unmapped() -> None:
    vault = render_obsidian_vault(_ctx(), resolve(["smb"]))
    assert "unmapped.md" not in vault


def test_vault_writes_unmapped_file_when_unmapped_services_present() -> None:
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
    vault = render_obsidian_vault(_ctx(unmapped=unmapped), resolve(["smb"]))
    assert "unmapped.md" in vault
    assert "9999/tcp" in vault["unmapped.md"]
    assert "abyss" in vault["unmapped.md"]


def test_service_note_has_yaml_frontmatter() -> None:
    vault = render_obsidian_vault(_ctx(), resolve(["smb"]))
    note = vault["services/smb.md"]

    assert note.startswith("---\n")
    assert "title: SMB" in note
    assert "target: 10.10.10.5" in note
    assert "service: smb" in note
    assert "priority: 10" in note
    assert "status: in-progress" in note
    assert "- methodology" in note
    assert "- smb" in note


def test_service_note_h1_uses_display_name() -> None:
    vault = render_obsidian_vault(_ctx(), resolve(["winrm"]))
    note = vault["services/winrm.md"]

    assert "\n# WinRM\n" in note
    # Section headers are h2 in per-service notes.
    assert "## Checklist" in note
    assert "## Commands" in note
    assert "## Expected output" in note
    assert "## Verification" in note
    assert "## Troubleshooting" in note
    assert "## Report note" in note


def test_service_note_substitutes_placeholders() -> None:
    vault = render_obsidian_vault(_ctx(), resolve(["smb"]))
    note = vault["services/smb.md"]

    assert "10.10.10.5" in note
    assert "[TARGET_IP]" not in note
    assert "[USER]" in note  # operator placeholders preserved
    assert "[PASS]" in note


def test_service_note_emits_related_wikilinks_with_aliases() -> None:
    vault = render_obsidian_vault(_ctx(), resolve(["smb"]))
    note = vault["services/smb.md"]

    assert "## Related" in note
    assert "[[services/ldap|LDAP]]" in note
    assert "[[services/kerberos|Kerberos]]" in note


def test_service_note_omits_related_section_when_empty() -> None:
    ftp = lookup("ftp")
    assert ftp is not None and ftp.related == ()
    vault = render_obsidian_vault(_ctx(), resolve(["ftp"]))
    note = vault["services/ftp.md"]
    assert "## Related" not in note


def test_index_lists_each_workflow_as_aliased_wikilink() -> None:
    workflows = resolve(["smb", "http", "rdp"])
    vault = render_obsidian_vault(_ctx(), workflows)
    index = vault["index.md"]

    assert "[[services/smb|SMB]]" in index
    assert "[[services/http|HTTP]]" in index
    assert "[[services/rdp|RDP]]" in index


def test_index_links_to_unmapped_note_when_present() -> None:
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
    vault = render_obsidian_vault(_ctx(unmapped=unmapped), resolve(["smb"]))
    assert "[[unmapped|Unmapped Services]]" in vault["index.md"]


def test_index_skips_unmapped_section_when_none() -> None:
    vault = render_obsidian_vault(_ctx(), resolve(["smb"]))
    assert "Unmapped Services" not in vault["index.md"]


def test_index_includes_after_foothold_section() -> None:
    vault = render_obsidian_vault(_ctx(), resolve(["smb"]))
    index = vault["index.md"]

    assert "## After a Foothold" in index
    assert "cpts-tools workflow show linux-privesc" in index
    assert "cpts-tools workflow show pivoting" in index
    # No per-service notes are created for post-foothold workflows.
    assert "services/linux-privesc.md" not in vault
    assert "services/pivoting.md" not in vault


def test_index_has_methodology_moc_tags() -> None:
    vault = render_obsidian_vault(_ctx(), resolve(["smb"]))
    index = vault["index.md"]

    assert "title: Methodology — 10.10.10.5" in index
    assert "- methodology" in index
    assert "- moc" in index


def test_index_keeps_target_host_placeholder_when_missing() -> None:
    vault = render_obsidian_vault(
        _ctx(target_host=None, domain=None),
        resolve(["smb"]),
    )
    index = vault["index.md"]
    assert "[TARGET_HOST]" in index
    assert "[DOMAIN]" in index


def test_no_workflows_still_produces_index() -> None:
    vault = render_obsidian_vault(_ctx(), [])
    assert set(vault) == {"index.md"}
    assert "_No workflow matched the detected services._" in vault["index.md"]
