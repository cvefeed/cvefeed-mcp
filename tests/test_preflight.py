"""Tests for the startup preflight in ``cvefeed_mcp.__main__``.

Each failure mode exits with a distinct code so Claude Desktop / Cursor can
surface actionable guidance in their MCP log; we lock those codes in here.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from cvefeed_mcp.__main__ import (
    EXIT_AUTH_FAILED,
    EXIT_PREFLIGHT_FAILED,
    EXIT_PROJECT_ID_MISSING,
    EXIT_TIER_DENIED,
    EXIT_TOKEN_MISSING,
    _build_client,
    _preflight,
)
from cvefeed_mcp.client import CvefeedClient
from cvefeed_mcp.errors import CvefeedAuthError, CvefeedServerError


def _client_with(
    handler,
    *,
    token: str | None = "cvefeed_TEST1234_secretvalue",
    project_id: int | None = 42,
) -> CvefeedClient:
    return CvefeedClient(
        base_url="https://api.test",
        token=token,
        project_id=project_id,
        transport=httpx.MockTransport(handler),
    )


def _context_response(
    *,
    tier_name: str,
    tier_allows_mcp: bool,
    token_is_mcp_enabled: bool,
) -> dict:
    """Shape-compatible with ``/api/projects/<id>/`` response.

    The server exposes the tier feature flag and the token capability flag
    separately; no precomputed effective field. Preflight ANDs them itself.
    """
    return {
        "id": 42,
        "name": "test",
        "slug": "test",
        "tier": {
            "name": tier_name,
            "priority": 1,
            "features": {"mcp_access": {"enabled": tier_allows_mcp, "limit": 0}},
        },
        "token": {
            "prefix": "TEST1234",
            "scopes": {},
            "is_mcp_enabled": token_is_mcp_enabled,
        },
    }


class TestPreflight:
    def test_missing_token_exits_with_token_missing_code(self, capsys):
        client = _client_with(lambda _: httpx.Response(200, json={}), token=None)
        with pytest.raises(SystemExit) as exc:
            _preflight(client)
        assert exc.value.code == EXIT_TOKEN_MISSING

        stderr = capsys.readouterr().err
        assert "CVEFEED_API_TOKEN" in stderr
        assert "/project/settings/api-tokens/" in stderr

    def test_missing_project_id_exits_with_project_id_missing_code(self, capsys):
        client = _client_with(lambda _: httpx.Response(200, json={}), project_id=None)
        with pytest.raises(SystemExit) as exc:
            _preflight(client)
        assert exc.value.code == EXIT_PROJECT_ID_MISSING

        stderr = capsys.readouterr().err
        assert "CVEFEED_PROJECT_ID" in stderr
        assert "numeric id" in stderr

    def test_non_numeric_project_id_exits_via_build_client(self, capsys, monkeypatch):
        # Build path: a bad CVEFEED_PROJECT_ID raises ValueError inside the
        # client constructor; _build_client maps that to EXIT_PROJECT_ID_MISSING
        # with a clear message rather than letting the traceback escape.
        monkeypatch.setenv("CVEFEED_PROJECT_ID", "not-a-number")
        monkeypatch.setenv("CVEFEED_API_TOKEN", "cvefeed_TEST1234_abc")

        with pytest.raises(SystemExit) as exc:
            _build_client()
        assert exc.value.code == EXIT_PROJECT_ID_MISSING
        assert "must be an integer" in capsys.readouterr().err

    def test_auth_error_exits_with_auth_failed_code(self, capsys):
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"detail": "Invalid."})

        with pytest.raises(SystemExit) as exc:
            _preflight(_client_with(handler))
        assert exc.value.code == EXIT_AUTH_FAILED
        assert "cvefeed-mcp" in capsys.readouterr().err

    def test_free_tier_exits_with_tier_denied_code(self, capsys):
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_context_response(
                    tier_name="free",
                    tier_allows_mcp=False,
                    token_is_mcp_enabled=False,
                ),
            )

        with pytest.raises(SystemExit) as exc:
            _preflight(_client_with(handler))
        assert exc.value.code == EXIT_TIER_DENIED

        stderr = capsys.readouterr().err
        assert "FREE" in stderr
        assert "Pro tier" in stderr
        assert "/subscription/" in stderr

    def test_starter_tier_also_denied(self, capsys):
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_context_response(
                    tier_name="starter",
                    tier_allows_mcp=False,
                    token_is_mcp_enabled=False,
                ),
            )

        with pytest.raises(SystemExit) as exc:
            _preflight(_client_with(handler))
        assert exc.value.code == EXIT_TIER_DENIED
        assert "STARTER" in capsys.readouterr().err

    def test_pro_tier_with_mcp_enabled_token_passes(self):
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_context_response(
                    tier_name="pro",
                    tier_allows_mcp=True,
                    token_is_mcp_enabled=True,
                ),
            )

        assert _preflight(_client_with(handler)) is None

    def test_enterprise_with_mcp_enabled_token_passes(self):
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_context_response(
                    tier_name="enterprise",
                    tier_allows_mcp=True,
                    token_is_mcp_enabled=True,
                ),
            )

        assert _preflight(_client_with(handler)) is None

    def test_pro_tier_with_non_mcp_token_directs_user_to_reissue(self, capsys):
        # Owner is on Pro but the token itself was created without MCP enabled.
        # The error should steer the user toward re-issuing the token, not
        # upgrading their subscription.
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_context_response(
                    tier_name="pro",
                    tier_allows_mcp=True,
                    token_is_mcp_enabled=False,
                ),
            )

        with pytest.raises(SystemExit) as exc:
            _preflight(_client_with(handler))
        assert exc.value.code == EXIT_TIER_DENIED

        stderr = capsys.readouterr().err
        assert "does not have MCP enabled" in stderr
        assert "/project/settings/api-tokens/" in stderr
        # Must NOT suggest upgrading — the tier is already fine.
        assert "Upgrade" not in stderr

    def test_free_tier_with_mcp_enabled_token_blames_tier_not_token(self, capsys):
        # Historical capability (is_mcp_enabled=True) after a downgrade — the
        # server reports mcp_enabled=false because tier gate wins. Tell the
        # user to upgrade, not to re-issue a token.
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_context_response(
                    tier_name="free",
                    tier_allows_mcp=False,
                    token_is_mcp_enabled=True,
                ),
            )

        with pytest.raises(SystemExit) as exc:
            _preflight(_client_with(handler))
        assert exc.value.code == EXIT_TIER_DENIED

        stderr = capsys.readouterr().err
        assert "FREE" in stderr
        assert "Upgrade" in stderr
        assert "does not have MCP enabled" not in stderr

    def test_generic_server_error_exits_with_preflight_failed_code(self, capsys):
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="upstream down")

        with pytest.raises(SystemExit) as exc:
            _preflight(_client_with(handler))
        assert exc.value.code == EXIT_PREFLIGHT_FAILED
        assert "preflight" in capsys.readouterr().err.lower()

    def test_exit_codes_are_distinct(self):
        # Codes must be distinct so log triage can classify failures without
        # parsing text — Claude Desktop surfaces the exit code separately.
        codes = {
            EXIT_TOKEN_MISSING,
            EXIT_AUTH_FAILED,
            EXIT_TIER_DENIED,
            EXIT_PREFLIGHT_FAILED,
            EXIT_PROJECT_ID_MISSING,
        }
        assert len(codes) == 5

    def test_get_project_context_called_exactly_once(self):
        # Preflight should not hammer the project endpoint — any retry logic
        # would mask a broken tier state and delay the exit message.
        client = MagicMock(spec=CvefeedClient)
        client.token = "cvefeed_TEST1234_abc"
        client.project_id = 42
        client.base_url = "https://api.test"
        client.get_project_context.return_value = _context_response(
            tier_name="pro",
            tier_allows_mcp=True,
            token_is_mcp_enabled=True,
        )

        _preflight(client)

        assert client.get_project_context.call_count == 1

    def test_non_auth_cvefeed_error_treated_as_preflight_failure(self, capsys):
        client = MagicMock(spec=CvefeedClient)
        client.token = "cvefeed_TEST1234_abc"
        client.project_id = 42
        client.base_url = "https://api.test"
        client.get_project_context.side_effect = CvefeedServerError("boom")

        with pytest.raises(SystemExit) as exc:
            _preflight(client)
        assert exc.value.code == EXIT_PREFLIGHT_FAILED
        stderr = capsys.readouterr().err
        assert "boom" in stderr
        assert "/api/projects/42/" in stderr

    def test_auth_error_takes_precedence_over_preflight_failed(self, capsys):
        # CvefeedAuthError is a subclass of CvefeedError; make sure the more
        # specific auth handler runs first and emits the auth-failed code.
        client = MagicMock(spec=CvefeedClient)
        client.token = "cvefeed_TEST1234_abc"
        client.project_id = 42
        client.base_url = "https://api.test"
        client.get_project_context.side_effect = CvefeedAuthError("token rejected")

        with pytest.raises(SystemExit) as exc:
            _preflight(client)
        assert exc.value.code == EXIT_AUTH_FAILED
