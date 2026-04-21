"""Unit tests for :class:`cvefeed_mcp.client.CvefeedClient`.

Every error-path assertion is load-bearing: MCP tool error messages are the
only way agents recover from misconfigured tokens, missing scopes, or rate
limits, so the mapping from HTTP failure -> CvefeedError subclass must stay
exact.
"""

from __future__ import annotations

import httpx
import pytest

from cvefeed_mcp.client import CvefeedClient
from cvefeed_mcp.errors import (
    CvefeedAuthError,
    CvefeedPermissionError,
    CvefeedRateLimitError,
    CvefeedServerError,
)
from tests.conftest import json_response


class TestAuthHeader:
    def test_bearer_token_attached_when_present(self, make_client):
        seen: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["auth"] = request.headers.get("authorization", "")
            return json_response({"ok": True})

        make_client(handler).quick_search("openssl")

        assert seen["auth"] == "Bearer cvefeed_TEST1234_secretvalue"

    def test_authorization_absent_without_token(self, make_client):
        seen: dict[str, str | None] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["auth"] = request.headers.get("authorization")
            return json_response({"ok": True})

        make_client(handler, token=None).quick_search("openssl")

        assert seen["auth"] is None

    def test_user_agent_is_versioned(self, make_client):
        seen: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["ua"] = request.headers.get("user-agent", "")
            return json_response({"ok": True})

        make_client(handler).quick_search("openssl")

        assert seen["ua"].startswith("cvefeed-mcp/")


class TestRequestShape:
    def test_search_cves_emits_drf_advanced_search_with_filters(self, make_client):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["method"] = request.method
            return json_response({"count": 0, "results": []})

        make_client(handler).search_cves(
            query="openssl",
            severity="critical",
            published_after="2026-01-01",
            page=2,
        )

        assert seen["method"] == "GET"
        url = seen["url"]
        assert "https://api.test/api/vulnerability/advanced-search" in url
        assert "q=openssl" in url
        assert "severity=critical" in url
        assert "published_after=2026-01-01" in url
        assert "page=2" in url

    def test_none_filters_are_dropped_from_query_string(self, make_client):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            return json_response({"count": 0, "results": []})

        make_client(handler).search_cves(query="openssl")

        # Only non-None params should be serialized.
        url = seen["url"]
        assert "q=openssl" in url
        assert "severity=" not in url
        assert "cvss_min=" not in url

    def test_add_subscriptions_posts_json_body(self, make_client):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["method"] = request.method
            seen["path"] = request.url.path
            seen["body"] = request.content.decode("utf-8")
            return json_response({"ok": True}, status_code=201)

        make_client(handler).add_subscriptions([1337, 9001])

        assert seen["method"] == "POST"
        assert seen["path"] == "/api/projects/42/products/"
        assert '"product_ids"' in seen["body"]
        assert "1337" in seen["body"]
        assert "9001" in seen["body"]

    def test_remove_subscriptions_sends_delete_with_body(self, make_client):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["method"] = request.method
            seen["path"] = request.url.path
            seen["body"] = request.content.decode("utf-8")
            return json_response({"ok": True})

        make_client(handler).remove_subscriptions([1337])

        assert seen["method"] == "DELETE"
        assert seen["path"] == "/api/projects/42/products/"
        assert "1337" in seen["body"]

    def test_list_alerts_unread_only_maps_to_is_read_false(self, make_client):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["path"] = request.url.path
            return json_response({"count": 0, "results": []})

        make_client(handler).list_alerts(is_read=False)

        assert seen["path"] == "/api/projects/42/alerts/"
        assert "is_read=false" in seen["url"]

    def test_cveql_validate_posts_query(self, make_client):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["path"] = request.url.path
            seen["body"] = request.content.decode("utf-8")
            return json_response({"valid": True})

        make_client(handler).cveql_validate("severity:critical")

        assert seen["path"] == "/api/cveql/validate/"
        assert '"query"' in seen["body"]
        assert "severity:critical" in seen["body"]

    def test_cveql_search_omits_page_when_none(self, make_client):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["body"] = request.content.decode("utf-8")
            return json_response({"count": 0, "results": []})

        make_client(handler).cveql_search("severity:critical")

        assert '"page"' not in seen["body"]

    def test_mark_alert_read_posts_to_nested_path(self, make_client):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["method"] = request.method
            seen["path"] = request.url.path
            return httpx.Response(204)

        result = make_client(handler).mark_alert_read(9)

        assert seen["method"] == "POST"
        assert seen["path"] == "/api/projects/42/alerts/9/mark-as-read/"
        assert result is None  # empty body -> None


class TestCveIdValidation:
    """``cve_id`` is interpolated into the URL path; must be validated before.

    A path-traversal attempt (``../foo``), a trailing slash, or a bare ``CVE``
    prefix without digits should all be rejected **before** we issue the HTTP
    request — otherwise we either hit the wrong DRF route or leak a confusing
    404 from the server.
    """

    @pytest.mark.parametrize(
        "bad_id",
        [
            "../../etc/passwd",
            "CVE-2026-1/../../something",
            "CVE-2026-",
            "CVE-2026-12",  # only 2 digits — sequence part requires 4+
            "not-a-cve",
            "",
            "CVE-abc-1234",
            "CVE-2026-1234 OR 1=1",
        ],
    )
    def test_get_cve_rejects_invalid_id_without_network_call(self, make_client, bad_id):
        def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("validator must fail before any HTTP request")

        with pytest.raises(ValueError, match="Invalid CVE id"):
            make_client(handler).get_cve(bad_id)

    def test_get_cve_change_history_also_validates(self, make_client):
        def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("validator must fail before any HTTP request")

        with pytest.raises(ValueError, match="Invalid CVE id"):
            make_client(handler).get_cve_change_history("../escape")

    def test_get_cve_normalizes_case_and_strips_whitespace(self, make_client):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["path"] = request.url.path
            return json_response({"id": "CVE-2026-12345"})

        make_client(handler).get_cve("  cve-2026-12345  ")
        assert captured["path"] == "/api/vulnerability/CVE-2026-12345/"

    def test_valid_cve_id_is_forwarded(self, make_client):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["path"] = request.url.path
            return json_response({"id": "CVE-2026-12345"})

        make_client(handler).get_cve("CVE-2026-12345")
        assert captured["path"] == "/api/vulnerability/CVE-2026-12345/"


class TestErrorMapping:
    def test_401_raises_auth_error_with_guidance(self, make_client):
        def handler(_: httpx.Request) -> httpx.Response:
            return json_response({"detail": "Invalid token."}, status_code=401)

        with pytest.raises(CvefeedAuthError) as exc:
            make_client(handler).quick_search("openssl")

        assert "CVEFEED_API_TOKEN" in str(exc.value)

    def test_403_raises_permission_error_with_scope_and_tier(self, make_client):
        def handler(_: httpx.Request) -> httpx.Response:
            return json_response(
                {"detail": "Insufficient scope."},
                status_code=403,
                headers={
                    "X-Required-Scope": "subscriptions:write",
                    "X-Required-Tier": "pro",
                },
            )

        with pytest.raises(CvefeedPermissionError) as exc:
            make_client(handler).add_subscriptions([1])

        assert "Insufficient scope." in str(exc.value)
        assert exc.value.required_scope == "subscriptions:write"
        assert exc.value.required_tier == "pro"

    def test_429_raises_rate_limit_error_with_retry_after(self, make_client):
        def handler(_: httpx.Request) -> httpx.Response:
            return json_response(
                {"detail": "Throttled."},
                status_code=429,
                headers={"Retry-After": "60"},
            )

        with pytest.raises(CvefeedRateLimitError) as exc:
            make_client(handler).quick_search("openssl")

        assert exc.value.retry_after == 60
        assert "60 seconds" in str(exc.value)

    def test_429_without_retry_after_header_is_still_mapped(self, make_client):
        def handler(_: httpx.Request) -> httpx.Response:
            return json_response({"detail": "Throttled."}, status_code=429)

        with pytest.raises(CvefeedRateLimitError) as exc:
            make_client(handler).quick_search("openssl")

        assert exc.value.retry_after is None

    def test_5xx_raises_server_error(self, make_client):
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(502, text="Bad Gateway")

        with pytest.raises(CvefeedServerError):
            make_client(handler).quick_search("openssl")

    def test_transport_failure_raises_server_error(self, make_client):
        def handler(_: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom")

        with pytest.raises(CvefeedServerError) as exc:
            make_client(handler).quick_search("openssl")

        assert "unreachable" in str(exc.value)

    def test_other_4xx_raises_server_error_with_detail(self, make_client):
        def handler(_: httpx.Request) -> httpx.Response:
            return json_response({"detail": "bad input"}, status_code=400)

        with pytest.raises(CvefeedServerError) as exc:
            make_client(handler).search_cves(query="x")

        assert "bad input" in str(exc.value)


class TestSuccessDecoding:
    def test_json_body_returned_as_dict(self, make_client):
        def handler(_: httpx.Request) -> httpx.Response:
            return json_response({"count": 1, "results": [{"id": "CVE-2026-1"}]})

        result = make_client(handler).quick_search("openssl")
        assert result["count"] == 1
        assert result["results"][0]["id"] == "CVE-2026-1"

    def test_empty_response_body_returns_none(self, make_client):
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(204)

        assert make_client(handler).mark_alert_read(2) is None


class TestGetProjectContext:
    def test_hits_project_detail_endpoint(self, make_client):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["path"] = request.url.path
            return json_response(
                {
                    "id": 42,
                    "name": "test",
                    "slug": "test",
                    "tier": {
                        "name": "pro",
                        "priority": 3,
                        "features": {"mcp_access": {"enabled": True, "limit": 0}},
                    },
                    "token": {
                        "prefix": "ABCD1234",
                        "scopes": {},
                        "is_mcp_enabled": True,
                    },
                },
            )

        result = make_client(handler).get_project_context()

        assert captured["path"] == "/api/projects/42/"
        # The effective MCP flag is the AND of tier + token capability; caller
        # computes it, the API does not precompute a derived field.
        assert result["tier"]["features"]["mcp_access"]["enabled"] is True
        assert result["token"]["is_mcp_enabled"] is True

    def test_401_surfaces_auth_error(self, make_client):
        def handler(_: httpx.Request) -> httpx.Response:
            return json_response({"detail": "no token"}, status_code=401)

        with pytest.raises(CvefeedAuthError):
            make_client(handler).get_project_context()


class TestEnvironmentDefaults:
    def test_base_url_env_var_is_respected(self, monkeypatch):
        monkeypatch.setenv("CVEFEED_BASE_URL", "https://staging.cvefeed.io")
        monkeypatch.delenv("CVEFEED_API_TOKEN", raising=False)
        monkeypatch.delenv("CVEFEED_PROJECT_ID", raising=False)

        client = CvefeedClient(transport=httpx.MockTransport(lambda _: json_response({})))

        assert client.base_url == "https://staging.cvefeed.io"
        assert client.token is None
        assert client.project_id is None

    def test_token_env_var_is_respected(self, monkeypatch):
        monkeypatch.setenv("CVEFEED_API_TOKEN", "cvefeed_ENV12345_abc")
        monkeypatch.delenv("CVEFEED_BASE_URL", raising=False)
        monkeypatch.delenv("CVEFEED_PROJECT_ID", raising=False)

        client = CvefeedClient(transport=httpx.MockTransport(lambda _: json_response({})))
        assert client.token == "cvefeed_ENV12345_abc"

    def test_project_id_env_var_is_respected(self, monkeypatch):
        monkeypatch.setenv("CVEFEED_PROJECT_ID", "7")
        monkeypatch.delenv("CVEFEED_API_TOKEN", raising=False)

        client = CvefeedClient(transport=httpx.MockTransport(lambda _: json_response({})))
        assert client.project_id == 7

    def test_non_integer_project_id_raises_value_error(self, monkeypatch):
        monkeypatch.setenv("CVEFEED_PROJECT_ID", "not-a-number")

        with pytest.raises(ValueError):
            CvefeedClient(transport=httpx.MockTransport(lambda _: json_response({})))

    def test_blank_project_id_env_var_is_treated_as_unset(self, monkeypatch):
        monkeypatch.setenv("CVEFEED_PROJECT_ID", "  ")

        client = CvefeedClient(transport=httpx.MockTransport(lambda _: json_response({})))
        assert client.project_id is None
