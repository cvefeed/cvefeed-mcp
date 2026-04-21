"""Entry point for ``python -m cvefeed_mcp`` and the ``cvefeed-mcp`` console script.

Preflights against ``/api/projects/<project_id>/`` so the client can refuse to
start (with an actionable upgrade / re-issue-token / set-env message) instead
of serving tools that would return 403s or 404s.
"""

from __future__ import annotations

import sys

from cvefeed_mcp.client import CvefeedClient
from cvefeed_mcp.errors import CvefeedAuthError, CvefeedError
from cvefeed_mcp.server import build_server

EXIT_TOKEN_MISSING = 2
EXIT_AUTH_FAILED = 3
EXIT_TIER_DENIED = 4
EXIT_PREFLIGHT_FAILED = 5
EXIT_PROJECT_ID_MISSING = 6


def _tier_allows_mcp(me: dict) -> bool:
    tier = me.get("tier") or {}
    feature = (tier.get("features") or {}).get("mcp_access") or {}
    return bool(feature.get("enabled"))


def _token_has_mcp_capability(me: dict) -> bool:
    """Read the token's per-request capability flag.

    Effective MCP access is the AND of this flag and ``_tier_allows_mcp`` —
    the API deliberately does not precompute the AND so there is no derived
    value that can drift out of sync with tier/token state.
    """
    token = me.get("token") or {}
    return bool(token.get("is_mcp_enabled"))


def _build_client() -> CvefeedClient:
    """Build the client, mapping a bad ``CVEFEED_PROJECT_ID`` to a clean exit."""
    try:
        return CvefeedClient()
    except ValueError:
        sys.stderr.write(
            "cvefeed-mcp: CVEFEED_PROJECT_ID must be an integer. "
            "Set it to the numeric id of the project your token is bound to "
            "(find it in the URL of your project dashboard).\n",
        )
        sys.exit(EXIT_PROJECT_ID_MISSING)


def _preflight(client: CvefeedClient) -> None:
    """Verify the token is valid AND explicitly enabled for MCP.

    Exits the process with a distinct status code on each failure mode so
    Claude Desktop / Cursor show an actionable message in their MCP log.
    """
    if not client.token:
        sys.stderr.write(
            "cvefeed-mcp: CVEFEED_API_TOKEN is not set. Create an MCP-enabled token at "
            f"{client.base_url}/project/settings/api-tokens/ and export it.\n",
        )
        sys.exit(EXIT_TOKEN_MISSING)

    if client.project_id is None:
        sys.stderr.write(
            "cvefeed-mcp: CVEFEED_PROJECT_ID is not set. Set it to the numeric id of "
            "the project your token is bound to — you can find the id in the URL of "
            f"your project's dashboard at {client.base_url}/project/detail/... .\n",
        )
        sys.exit(EXIT_PROJECT_ID_MISSING)

    try:
        me = client.get_project_context() or {}
    except CvefeedAuthError as exc:
        sys.stderr.write(f"cvefeed-mcp: {exc}\n")
        sys.exit(EXIT_AUTH_FAILED)
    except CvefeedError as exc:
        sys.stderr.write(
            f"cvefeed-mcp: preflight against /api/projects/{client.project_id}/ failed: {exc}. "
            "Check that CVEFEED_PROJECT_ID matches the project your token was issued for.\n",
        )
        sys.exit(EXIT_PREFLIGHT_FAILED)

    if _tier_allows_mcp(me) and _token_has_mcp_capability(me):
        return

    # Distinguish the two failure modes so users know which fix to apply.
    if not _tier_allows_mcp(me):
        tier_name = ((me.get("tier") or {}).get("name") or "unknown").upper()
        sys.stderr.write(
            f"cvefeed-mcp: MCP access is not included in your current tier ({tier_name}). "
            "It requires a Pro tier subscription or higher. "
            f"Upgrade at {client.base_url}/subscription/.\n",
        )
    else:
        # Tier is fine, so the token must have been created without MCP enabled.
        sys.stderr.write(
            "cvefeed-mcp: the configured token does not have MCP enabled. "
            "Create a new token with the MCP option checked at "
            f"{client.base_url}/project/settings/api-tokens/ and update CVEFEED_API_TOKEN.\n",
        )
    sys.exit(EXIT_TIER_DENIED)


def main() -> None:
    client = _build_client()
    _preflight(client)
    build_server(client).run(transport="stdio")


if __name__ == "__main__":
    main()
