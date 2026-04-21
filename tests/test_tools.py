"""Integration tests for the MCP tool layer.

The tools are thin wrappers over ``CvefeedClient``; their job is parameter
mapping, not business logic. These tests call each tool through the FastMCP
server exactly the way an MCP client would, and assert the outgoing HTTP
request shape (via MockTransport) plus the returned payload.
"""

from __future__ import annotations

import json

import httpx
import pytest

from cvefeed_mcp.client import CvefeedClient
from cvefeed_mcp.server import build_server
from tests.conftest import json_response


@pytest.fixture
def server_with_handler():
    """Build a FastMCP server whose CvefeedClient is wired to a fake HTTP handler."""

    def _build(handler, *, project_id: int | None = 42):
        client = CvefeedClient(
            base_url="https://api.test",
            token="cvefeed_TEST1234_secret",
            project_id=project_id,
            transport=httpx.MockTransport(handler),
        )
        return build_server(client)

    return _build


async def call_tool(server, name: str, arguments: dict) -> dict:
    """Invoke a FastMCP tool and return its JSON-decoded payload.

    FastMCP returns content blocks; when the tool returns a dict/list, the SDK
    serializes it into a structuredContent block + a text block. We want the
    structured view for assertion purposes.
    """
    result = await server.call_tool(name, arguments)
    # FastMCP >=1.2 returns a tuple (content_blocks, structured) from call_tool;
    # older versions return a list of content blocks. Handle both.
    if isinstance(result, tuple) and len(result) == 2:
        _content, structured = result
        return structured
    # Fallback: find the first text block and parse it.
    for block in result:
        text = getattr(block, "text", None)
        if text:
            return json.loads(text)
    raise AssertionError(f"tool {name!r} returned no usable content: {result!r}")


class TestToolRegistration:
    async def test_all_expected_tools_are_registered(self, server_with_handler):
        server = server_with_handler(lambda _: json_response({}))
        tools = await server.list_tools()
        names = {t.name for t in tools}

        # Exactly the surface promised by the SKILL.md registry + cveql_schema helper.
        assert names == {
            "search_cves",
            "get_cve_detail",
            "run_cveql_query",
            "cveql_schema",
            "lookup_by_cpe",
            "get_exploit_intel",
            "list_product_subscriptions",
            "add_product_subscription",
            "remove_product_subscription",
            "search_products",
            "list_project_alerts",
            "mark_alert_read",
            "read_project_activity_log",
        }

    async def test_every_tool_has_a_description(self, server_with_handler):
        server = server_with_handler(lambda _: json_response({}))
        tools = await server.list_tools()
        for tool in tools:
            assert tool.description, f"tool {tool.name} missing description"


class TestToolInvocation:
    async def test_search_cves_maps_to_advanced_search(self, server_with_handler):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            return json_response({"count": 0, "results": []})

        server = server_with_handler(handler)
        result = await call_tool(server, "search_cves", {"query": "openssl", "severity": "critical"})

        assert result == {"count": 0, "results": []}
        assert "/api/vulnerability/advanced-search" in captured["url"]
        assert "q=openssl" in captured["url"]
        assert "severity=critical" in captured["url"]

    async def test_get_cve_detail_without_history(self, server_with_handler):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/vulnerability/CVE-2026-1234/"
            return json_response({"id": "CVE-2026-1234", "severity": "high"})

        server = server_with_handler(handler)
        result = await call_tool(server, "get_cve_detail", {"cve_id": "CVE-2026-1234"})

        assert result == {"id": "CVE-2026-1234", "severity": "high"}

    async def test_get_cve_detail_with_history_issues_two_requests(self, server_with_handler):
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            if request.url.path.endswith("/change-history/"):
                return json_response([{"changed_at": "2026-04-01"}])
            return json_response({"id": "CVE-2026-1234"})

        server = server_with_handler(handler)
        result = await call_tool(
            server,
            "get_cve_detail",
            {"cve_id": "CVE-2026-1234", "include_change_history": True},
        )

        assert set(result.keys()) == {"detail", "change_history"}
        assert result["detail"]["id"] == "CVE-2026-1234"
        assert result["change_history"][0]["changed_at"] == "2026-04-01"
        assert sorted(calls) == [
            "/api/vulnerability/CVE-2026-1234/",
            "/api/vulnerability/CVE-2026-1234/change-history/",
        ]

    async def test_get_cve_detail_rejects_malformed_cve_id(self, server_with_handler):
        # The pydantic ``pattern`` constraint on the tool field must trip
        # before the handler runs — an agent passing a path-traversal attempt
        # should get a tool-schema error, not a backend 404.
        def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("tool must reject invalid cve_id before HTTP")

        server = server_with_handler(handler)
        with pytest.raises(Exception, match="(?i)pattern|invalid|string_pattern"):
            await call_tool(server, "get_cve_detail", {"cve_id": "../../etc/passwd"})

    async def test_run_cveql_query_execute_vs_validate(self, server_with_handler):
        captured_paths: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_paths.append(request.url.path)
            return json_response({"ok": True})

        server = server_with_handler(handler)
        await call_tool(
            server,
            "run_cveql_query",
            {"query": "severity:critical", "validate_only": True},
        )
        await call_tool(server, "run_cveql_query", {"query": "severity:critical"})

        assert captured_paths == [
            "/api/cveql/validate/",
            "/api/cveql/search/",
        ]

    async def test_lookup_by_cpe_default_includes_all_three(self, server_with_handler):
        paths: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            paths.append(request.url.path)
            return json_response({"results": []})

        server = server_with_handler(handler)
        result = await call_tool(
            server,
            "lookup_by_cpe",
            {"cpe": "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"},
        )

        assert set(result.keys()) == {"cves", "products", "vendors"}
        assert sorted(paths) == [
            "/api/product/list-by-cpe",
            "/api/vendor/list-by-cpe",
            "/api/vulnerability/list-by-cpe",
        ]

    async def test_lookup_by_cpe_narrowed_include(self, server_with_handler):
        paths: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            paths.append(request.url.path)
            return json_response({"results": []})

        server = server_with_handler(handler)
        result = await call_tool(
            server,
            "lookup_by_cpe",
            {"cpe": "cpe:2.3:a:x:x:1:*:*:*:*:*:*:*", "include": ["cves"]},
        )

        assert set(result.keys()) == {"cves"}
        assert paths == ["/api/vulnerability/list-by-cpe"]

    async def test_list_product_subscriptions_hits_project_path(self, server_with_handler):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["path"] = request.url.path
            return json_response({"product_subscriptions": []})

        server = server_with_handler(handler)
        # No project_id in the tool call — the client injects it from its
        # constructor (env-var path in production, fixture default in tests).
        await call_tool(server, "list_product_subscriptions", {})

        assert captured["path"] == "/api/projects/42/products/"

    async def test_mark_alert_read_returns_ok_on_204(self, server_with_handler):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/projects/42/alerts/9/mark-as-read/"
            return httpx.Response(204)

        server = server_with_handler(handler)
        result = await call_tool(server, "mark_alert_read", {"alert_id": 9})

        assert result == {"ok": True}

    async def test_list_project_alerts_unread_only_flag(self, server_with_handler):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["path"] = request.url.path
            return json_response({"results": []})

        server = server_with_handler(handler)
        await call_tool(server, "list_project_alerts", {"unread_only": True})

        assert captured["path"] == "/api/projects/42/alerts/"
        assert "is_read=false" in captured["url"]

    async def test_project_scoped_tools_omit_project_id_from_schema(self, server_with_handler):
        # Guard: the LLM must not see a project_id parameter on any tool.
        # If one slipped through, agents would have to guess or ask the user.
        server = server_with_handler(lambda _: json_response({}))
        tools = await server.list_tools()
        project_scoped = {
            "list_product_subscriptions",
            "add_product_subscription",
            "remove_product_subscription",
            "search_products",
            "list_project_alerts",
            "mark_alert_read",
            "read_project_activity_log",
        }
        for tool in tools:
            if tool.name in project_scoped:
                props = (tool.inputSchema or {}).get("properties") or {}
                assert "project_id" not in props, f"tool {tool.name!r} still exposes project_id to the LLM"
