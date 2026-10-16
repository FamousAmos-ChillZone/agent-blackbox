"""The dashboard's Docs page (dashboard/docs_routes): what it serves and what its data may hold.

The page is served with an exact asset allowlist; ``/api/docs`` is built live from the shields
registry, so every supported wallet appears with its store availability, and no attack-table
row ever carries a test command (those live with the tests, never in what the plugin ships).
The page's own files load nothing from outside the dashboard, and the dashboard links to it.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import shields
from plugins.blackbox.dashboard import docs_routes, server
from plugins.blackbox.dashboard.docs_routes import payload

LOCAL = "http://127.0.0.1:9700"
#: Any absolute URL a page file could load from (links inside the data are drawn by docs.js).
EXTERNAL_LOAD = re.compile(r"""(?:src|href)\s*=\s*["']\s*(?:https?:)?//|url\(\s*["']?\s*(?:https?:)?//|@import""", re.IGNORECASE)


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("HOME", str(tmp_path_factory.mktemp("home")))   # never the real ~/.hermes
        with TestClient(server.create_app(), base_url=LOCAL) as test_client:
            yield test_client


@pytest.fixture(scope="module")
def docs() -> payload.DocsPayload:
    return payload.build_payload()


def test_the_page_is_served_as_html(client):
    answer = client.get("/docs")
    assert answer.status_code == 200
    assert answer.headers["content-type"].startswith("text/html")
    assert '<script src="/docs/assets/docs.js"' in answer.text


@pytest.mark.parametrize("name, media_type", sorted(docs_routes.ASSETS.items()))
def test_each_allowed_asset_is_served_with_its_type(client, name, media_type):
    answer = client.get(f"/docs/assets/{name}")
    assert answer.status_code == 200
    assert answer.headers["content-type"].startswith(media_type)


@pytest.mark.parametrize("name", ["docs.html", "payload.py", "__init__.py", "field_tests.json", "..%2Fpayload.py", "DOCS.CSS"])
def test_anything_off_the_allowlist_is_404(client, name):
    assert client.get(f"/docs/assets/{name}").status_code == 404


def test_the_docs_routes_refuse_a_foreign_host():
    with TestClient(server.create_app(), base_url="http://attacker.example") as foreign:
        assert {path: foreign.get(path).status_code for path in ("/docs", "/docs/assets/docs.js", "/api/docs")} == \
            {"/docs": 403, "/docs/assets/docs.js": 403, "/api/docs": 403}


def test_api_docs_answers_with_the_payload_shape(client):
    answer = client.get("/api/docs")
    assert answer.status_code == 200
    body = answer.json()
    assert set(body) == {"version", "shields", "field_tests"}
    assert isinstance(body["shields"], list)


def test_every_registered_shield_is_documented(docs):
    assert [shield["id"] for shield in docs["shields"]] == [shield.id for shield in shields.all_shields()]


def test_every_supported_pack_is_listed_with_its_stores_and_availability(docs):
    for shield in shields.all_shields():
        documented = {pack["id"]: pack for doc in docs["shields"] if doc["id"] == shield.id for pack in doc["packs"]}
        for pack in shields.loaded_packs(shield.id):
            if pack.status != "supported":
                continue
            assert pack.id in documented
            if pack.kind == "browser-extension":
                assert documented[pack.id]["stores"], pack.id
                assert documented[pack.id]["availability"], f"{pack.id} must say where it can and cannot be installed"


def test_no_attack_row_carries_more_than_the_page_fields(docs):
    for shield in docs["shields"]:
        rows = shield["attacks"]["rows"]
        assert rows, shield["id"]
        for row in rows:
            assert set(row) <= set(payload.ATTACK_FIELDS), row["id"]


def test_the_attack_table_matches_the_shield_page_row_for_row(docs):
    from plugins.blackbox.dashboard.shields_routes import attacks_payload

    for shield in docs["shields"]:
        assert [row["id"] for row in shield["attacks"]["rows"]] == [row["id"] for row in attacks_payload(shield["id"])["attacks"]]


def test_field_tests_are_read_and_a_broken_file_is_an_empty_list(docs, tmp_path, monkeypatch, caplog):
    assert docs["field_tests"] and all({"title", "date", "results"} <= set(run) for run in docs["field_tests"])
    broken = tmp_path / "field_tests.json"
    broken.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(payload, "FIELD_TESTS_FILE", broken)
    assert payload.build_payload()["field_tests"] == []
    assert "field tests could not be read" in caplog.text


@pytest.mark.parametrize("name", ["docs.html", *docs_routes.ASSETS])
def test_the_page_files_load_nothing_from_outside_the_dashboard(name):
    text = (docs_routes.HERE / name).read_text(encoding="utf-8")
    assert not EXTERNAL_LOAD.search(text), f"{name} loads an outside resource"


def test_docs_js_never_writes_product_data_as_markup():
    script = (docs_routes.HERE / "docs.js").read_text(encoding="utf-8")
    assert "innerHTML" not in script and "insertAdjacentHTML" not in script and "document.write" not in script


def test_the_dashboard_links_to_the_docs():
    index = (docs_routes.HERE.parent / "static" / "index.html").read_text(encoding="utf-8")
    assert 'href="/docs"' in index
