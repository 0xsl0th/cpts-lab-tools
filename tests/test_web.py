import json
from pathlib import Path

from reconlab.web import (
    WebFormat,
    detect_format,
    filter_by_status,
    format_web_results,
    merge_web_results,
    parse_feroxbuster_json,
    parse_feroxbuster_text,
    parse_gobuster_text,
    parse_web_results,
)

FIXTURES = Path(__file__).parent / "fixtures"
FEROX_TEXT = FIXTURES / "sample_feroxbuster.txt"
FEROX_JSON = FIXTURES / "sample_feroxbuster.json"
GOBUSTER_TEXT = FIXTURES / "sample_gobuster.txt"


def test_parse_feroxbuster_text_extracts_rows() -> None:
    rows = parse_feroxbuster_text(FEROX_TEXT)

    assert rows
    by_url = {r["url"]: r for r in rows}
    admin = by_url["http://10.10.10.5/admin"]
    assert admin["status"] == "200"
    assert admin["method"] == "GET"
    assert admin["size"] == "1234"
    assert admin["words"] == "46"
    assert admin["lines"] == "4"
    assert admin["redirect"] == "-"


def test_parse_feroxbuster_text_captures_redirect_target() -> None:
    rows = parse_feroxbuster_text(FEROX_TEXT)
    login = next(r for r in rows if r["url"] == "http://10.10.10.5/login")
    assert login["status"] == "301"
    assert login["redirect"] == "/login/"


def test_parse_feroxbuster_text_strips_ansi_color_codes(tmp_path: Path) -> None:
    sample = tmp_path / "colored.txt"
    sample.write_text(
        "\x1b[32m        200      GET        4l       46w      1234c "
        "http://10.10.10.5/admin\x1b[0m\n",
        encoding="utf-8",
    )
    rows = parse_feroxbuster_text(sample)
    assert len(rows) == 1
    assert rows[0]["url"] == "http://10.10.10.5/admin"


def test_parse_feroxbuster_json_keeps_only_response_entries() -> None:
    rows = parse_feroxbuster_json(FEROX_JSON)

    # Fixture has 1 scan-config + 3 responses + 1 report — only the 3 responses survive.
    assert len(rows) == 3
    by_url = {r["url"]: r for r in rows}
    assert by_url["http://10.10.10.5/admin"]["status"] == "200"
    assert by_url["http://10.10.10.5/admin"]["size"] == "1234"


def test_parse_feroxbuster_json_tolerates_malformed_lines(tmp_path: Path) -> None:
    sample = tmp_path / "messy.json"
    sample.write_text(
        "\n".join(
            [
                "",  # blank line
                "not-json-at-all",
                "{malformed",
                json.dumps(
                    {
                        "type": "response",
                        "url": "http://target.corp.local/x",
                        "method": "GET",
                        "status": 200,
                        "content_length": 10,
                        "word_count": 1,
                        "line_count": 1,
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )
    rows = parse_feroxbuster_json(sample)
    assert len(rows) == 1
    assert rows[0]["url"] == "http://target.corp.local/x"


def test_parse_gobuster_text_extracts_paths_and_status() -> None:
    rows = parse_gobuster_text(GOBUSTER_TEXT)

    paths = {r["url"] for r in rows}
    assert "/admin" in paths
    assert all(r["method"] == "GET" for r in rows)
    assert all(r["words"] == "-" for r in rows)  # gobuster doesn't track words
    assert all(r["lines"] == "-" for r in rows)


def test_parse_gobuster_text_captures_redirect_target() -> None:
    rows = parse_gobuster_text(GOBUSTER_TEXT)
    login = next(r for r in rows if r["url"] == "/login")
    assert login["status"] == "302"
    assert login["redirect"] == "/login/"


def test_parse_gobuster_text_skips_banner_lines() -> None:
    rows = parse_gobuster_text(GOBUSTER_TEXT)
    for row in rows:
        # No banner garbage should sneak through.
        assert not row["url"].startswith("=")
        assert "Gobuster" not in row["url"]


def test_detect_format_recognizes_feroxbuster_json() -> None:
    assert detect_format(FEROX_JSON) is WebFormat.FEROXBUSTER_JSON


def test_detect_format_recognizes_gobuster_text() -> None:
    assert detect_format(GOBUSTER_TEXT) is WebFormat.GOBUSTER


def test_detect_format_recognizes_feroxbuster_text() -> None:
    assert detect_format(FEROX_TEXT) is WebFormat.FEROXBUSTER


def test_parse_web_results_auto_dispatches_per_format() -> None:
    assert parse_web_results(FEROX_TEXT, WebFormat.AUTO)
    assert parse_web_results(FEROX_JSON, WebFormat.AUTO)
    assert parse_web_results(GOBUSTER_TEXT, WebFormat.AUTO)


def test_parse_web_results_explicit_format_overrides_detection() -> None:
    # Forcing the wrong format on a gobuster file → empty result, not a crash.
    assert parse_web_results(GOBUSTER_TEXT, WebFormat.FEROXBUSTER) == []


def test_filter_by_status_keeps_only_listed() -> None:
    rows = [
        {"status": "200", "url": "/a"},
        {"status": "301", "url": "/b"},
        {"status": "403", "url": "/c"},
    ]
    kept = filter_by_status(rows, ["200", "403"])
    assert {r["url"] for r in kept} == {"/a", "/c"}


def test_filter_by_status_none_means_no_filter() -> None:
    rows = [{"status": "200"}, {"status": "404"}]
    assert filter_by_status(rows, None) == rows


def test_format_web_results_handles_empty_input() -> None:
    assert format_web_results([]) == "No results found."


def test_format_web_results_includes_headers_and_data() -> None:
    output = format_web_results(parse_feroxbuster_text(FEROX_TEXT))

    for header in ("Status", "Method", "Size", "Words", "Lines", "URL"):
        assert header in output
    assert "200" in output
    assert "http://10.10.10.5/admin" in output


def test_format_web_results_inlines_redirect_target() -> None:
    output = format_web_results(parse_feroxbuster_text(FEROX_TEXT))
    # The /login row in the fixture is a 301 redirect to /login/.
    assert "http://10.10.10.5/login -> /login/" in output


def test_merge_web_results_handles_empty_input() -> None:
    assert merge_web_results([]) == []


def test_merge_web_results_dedupes_same_url_method_status() -> None:
    older = [
        {
            "status": "200", "method": "GET", "size": "100", "words": "5",
            "lines": "1", "url": "http://t/x", "redirect": "-",
        }
    ]
    newer = [
        {
            "status": "200", "method": "GET", "size": "1234", "words": "46",
            "lines": "4", "url": "http://t/x", "redirect": "-",
        }
    ]
    merged = merge_web_results(
        [(Path("older.json"), older), (Path("newer.json"), newer)]
    )

    assert len(merged) == 1
    # Newer non-placeholder values win for size/words/lines.
    assert merged[0]["size"] == "1234"
    assert merged[0]["words"] == "46"
    assert merged[0]["lines"] == "4"


def test_merge_web_results_unions_distinct_rows() -> None:
    a = [{"status": "200", "method": "GET", "size": "1", "words": "-",
          "lines": "-", "url": "http://t/a", "redirect": "-"}]
    b = [{"status": "200", "method": "GET", "size": "2", "words": "-",
          "lines": "-", "url": "http://t/b", "redirect": "-"}]
    merged = merge_web_results([(Path("a.txt"), a), (Path("b.txt"), b)])
    urls = {r["url"] for r in merged}
    assert urls == {"http://t/a", "http://t/b"}


def test_merge_web_results_placeholder_does_not_overwrite_real_data() -> None:
    older = [
        {
            "status": "200", "method": "GET", "size": "1234", "words": "46",
            "lines": "4", "url": "http://t/x", "redirect": "-",
        }
    ]
    newer = [
        {  # gobuster-style: no word/line data
            "status": "200", "method": "GET", "size": "1234", "words": "-",
            "lines": "-", "url": "http://t/x", "redirect": "-",
        }
    ]
    merged = merge_web_results(
        [(Path("older.json"), older), (Path("newer.txt"), newer)]
    )

    assert merged[0]["words"] == "46"
    assert merged[0]["lines"] == "4"


def test_merge_web_results_treats_method_status_url_as_compound_key() -> None:
    rows_a = [{"status": "200", "method": "GET", "size": "1", "words": "-",
               "lines": "-", "url": "http://t/x", "redirect": "-"}]
    rows_b = [{"status": "200", "method": "POST", "size": "2", "words": "-",
               "lines": "-", "url": "http://t/x", "redirect": "-"}]
    merged = merge_web_results([(Path("a.txt"), rows_a), (Path("b.txt"), rows_b)])
    # Same URL+status but different method → two rows.
    assert len(merged) == 2
