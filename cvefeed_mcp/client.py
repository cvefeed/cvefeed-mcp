"""HTTPX client wrapper around the CVEFeed.io REST API.

One method per tool-facing operation. Each method returns parsed JSON on
success or raises one of the :class:`CvefeedError` subclasses on a mapped
failure. This keeps the MCP tool layer declarative — tools just call into the
client and let exceptions propagate as tool errors.
"""

from __future__ import annotations

import os
import re
from typing import Any

import httpx

from cvefeed_mcp import __version__
from cvefeed_mcp.errors import (
    CvefeedAuthError,
    CvefeedError,
    CvefeedPermissionError,
    CvefeedRateLimitError,
    CvefeedServerError,
)

DEFAULT_BASE_URL = "https://cvefeed.io"
DEFAULT_TIMEOUT = 30.0
USER_AGENT = f"cvefeed-mcp/{__version__}"

# CVE identifiers are ``CVE-YYYY-N+`` with at least 4 numeric digits in the
# sequence part. Validating before URL interpolation prevents path traversal
# and ``//`` injection via user-controlled input.
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _validate_cve_id(value: str) -> str:
    """Normalize and validate a CVE ID; raise ValueError on mismatch."""
    normalized = (value or "").strip().upper()
    if not CVE_ID_PATTERN.fullmatch(normalized):
        msg = (
            f"Invalid CVE id: {value!r}. Expected format is 'CVE-YYYY-NNNNN' "
            "(four-digit year, at least four digits of sequence)."
        )
        raise ValueError(msg)
    return normalized


class CvefeedClient:
    """Thin authenticated wrapper over the CVEFeed REST API.

    Token, base URL, and project id default to the ``CVEFEED_API_TOKEN`` /
    ``CVEFEED_BASE_URL`` / ``CVEFEED_PROJECT_ID`` environment variables. Pass
    ``transport`` to inject an ``httpx.MockTransport`` for testing.

    ``project_id`` is required for every project-scoped tool. The client carries
    it so the LLM never has to guess — one MCP install targets exactly one
    project, matching the ``ProjectAPIToken`` FK constraint on the server.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        token: str | None = None,
        project_id: int | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = (base_url or os.environ.get("CVEFEED_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.token = token if token is not None else os.environ.get("CVEFEED_API_TOKEN")
        self.project_id = self._resolve_project_id(project_id)

        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        self._client = httpx.Client(
            base_url=self.base_url,
            headers=headers,
            timeout=timeout,
            transport=transport,
        )

    @staticmethod
    def _resolve_project_id(project_id: int | None) -> int | None:
        """Resolve ``project_id`` from argument or ``CVEFEED_PROJECT_ID`` env.

        Returns ``None`` if neither is set — the preflight surfaces that as an
        actionable error. A non-numeric env var raises ``ValueError`` so the
        preflight can catch it and exit cleanly.
        """
        if project_id is not None:
            return int(project_id)
        raw = os.environ.get("CVEFEED_PROJECT_ID")
        if raw is None or raw.strip() == "":
            return None
        return int(raw.strip())

    def _require_project_id(self) -> int:
        if self.project_id is None:
            raise CvefeedError(
                "CVEFEED_PROJECT_ID is not set — project-scoped tools cannot build a URL. "
                "Set the env var to the numeric id of the project your token is bound to.",
            )
        return self.project_id

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> CvefeedClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Core request helper
    # ------------------------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
    ) -> Any:
        try:
            response = self._client.request(
                method,
                path,
                params=_drop_none(params) if params else None,
                json=json,
            )
        except httpx.HTTPError as exc:
            raise CvefeedServerError(f"CVEFeed API unreachable: {exc}") from exc

        if response.status_code == 401:
            raise CvefeedAuthError(
                "CVEFeed rejected the API token. Check CVEFEED_API_TOKEN — "
                "the token must be active, not expired, and issued for the "
                "target project.",
            )
        if response.status_code == 403:
            detail = _extract_detail(response)
            raise CvefeedPermissionError(
                f"CVEFeed denied the request: {detail}. Check the token's "
                f"scope/tier at {self.base_url}/project/settings/api-tokens/.",
                required_scope=_header_or_none(response, "X-Required-Scope"),
                required_tier=_header_or_none(response, "X-Required-Tier"),
            )
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise CvefeedRateLimitError(
                "CVEFeed rate limit reached for this project. Wait "
                f"{retry_after or 'a moment'} seconds and retry. Per-project "
                "limits are tier-based; upgrade the project owner's tier for "
                "higher throughput.",
                retry_after=int(retry_after) if retry_after and retry_after.isdigit() else None,
            )
        if 500 <= response.status_code < 600:
            raise CvefeedServerError(
                f"CVEFeed API returned {response.status_code}: {response.text[:200]}",
            )
        if not response.is_success:
            detail = _extract_detail(response)
            raise CvefeedServerError(
                f"CVEFeed request failed ({response.status_code}): {detail}",
            )

        if not response.content:
            return None
        return response.json()

    # ------------------------------------------------------------------
    # Auth / context introspection
    # ------------------------------------------------------------------
    def get_project_context(self) -> Any:
        """Return the project + tier + auth context from ``/api/projects/<id>/``.

        Used as a preflight before registering MCP tools. Response includes
        ``tier.features.mcp_access`` and ``auth.token.mcp_enabled`` — the
        client refuses to serve tools when either is disabled.
        """
        pid = self._require_project_id()
        return self._request("GET", f"/api/projects/{pid}/")

    # ------------------------------------------------------------------
    # Vulnerability / global endpoints
    # ------------------------------------------------------------------
    def search_cves(
        self,
        *,
        query: str | None = None,
        severity: str | None = None,
        cvss_min: float | None = None,
        cvss_max: float | None = None,
        published_after: str | None = None,
        published_before: str | None = None,
        vendor: str | None = None,
        product: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> Any:
        return self._request(
            "GET",
            "/api/vulnerability/advanced-search",
            params={
                "q": query,
                "severity": severity,
                "cvss_min": cvss_min,
                "cvss_max": cvss_max,
                "published_after": published_after,
                "published_before": published_before,
                "vendor": vendor,
                "product": product,
                "page": page,
                "page_size": page_size,
            },
        )

    def quick_search(self, query: str) -> Any:
        return self._request(
            "GET",
            "/api/vulnerability/quick-search",
            params={"q": query},
        )

    def get_cve(self, cve_id: str) -> Any:
        safe_id = _validate_cve_id(cve_id)
        return self._request("GET", f"/api/vulnerability/{safe_id}/")

    def get_cve_change_history(self, cve_id: str) -> Any:
        safe_id = _validate_cve_id(cve_id)
        return self._request("GET", f"/api/vulnerability/{safe_id}/change-history/")

    def cveql_introspect(self) -> Any:
        return self._request("GET", "/api/cveql/introspect/")

    def cveql_validate(self, query: str) -> Any:
        return self._request("POST", "/api/cveql/validate/", json={"query": query})

    def cveql_search(self, query: str, *, page: int | None = None) -> Any:
        payload: dict[str, Any] = {"query": query}
        if page is not None:
            payload["page"] = page
        return self._request("POST", "/api/cveql/search/", json=payload)

    def vulnerabilities_by_cpe(self, cpe: str) -> Any:
        return self._request(
            "GET",
            "/api/vulnerability/list-by-cpe",
            params={"cpe": cpe},
        )

    def products_by_cpe(self, cpe: str) -> Any:
        return self._request(
            "GET",
            "/api/product/list-by-cpe",
            params={"cpe": cpe},
        )

    def vendors_by_cpe(self, cpe: str) -> Any:
        return self._request(
            "GET",
            "/api/vendor/list-by-cpe",
            params={"cpe": cpe},
        )

    def list_exploit_intel(
        self,
        *,
        cve_id: str | None = None,
        page: int | None = None,
    ) -> Any:
        return self._request(
            "GET",
            "/api/exploit-intel/",
            params={"cve_id": cve_id, "page": page},
        )

    def get_epss(
        self,
        *,
        cve_id: str | None = None,
        date: str | None = None,
        score_min: float | None = None,
        score_max: float | None = None,
    ) -> Any:
        return self._request(
            "GET",
            "/api/epss/",
            params={
                "cve_id": cve_id,
                "date": date,
                "score_min": score_min,
                "score_max": score_max,
            },
        )

    # ------------------------------------------------------------------
    # Project-scoped endpoints
    #
    # Every call uses ``self.project_id`` (sourced from ``CVEFEED_PROJECT_ID``).
    # The LLM never supplies a project id — one MCP install targets exactly one
    # project, same as the token's FK on the server.
    # ------------------------------------------------------------------
    def list_subscriptions(self) -> Any:
        pid = self._require_project_id()
        return self._request("GET", f"/api/projects/{pid}/products/")

    def add_subscriptions(self, product_ids: list[int]) -> Any:
        pid = self._require_project_id()
        return self._request(
            "POST",
            f"/api/projects/{pid}/products/",
            json={"product_ids": product_ids},
        )

    def remove_subscriptions(self, product_ids: list[int]) -> Any:
        pid = self._require_project_id()
        return self._request(
            "DELETE",
            f"/api/projects/{pid}/products/",
            json={"product_ids": product_ids},
        )

    def search_products(
        self,
        *,
        query: str,
        page: int | None = None,
    ) -> Any:
        pid = self._require_project_id()
        return self._request(
            "GET",
            f"/api/projects/{pid}/products/search/",
            params={"q": query, "page": page},
        )

    def list_alerts(
        self,
        *,
        is_read: bool | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> Any:
        pid = self._require_project_id()
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if is_read is not None:
            params["is_read"] = "true" if is_read else "false"
        return self._request("GET", f"/api/projects/{pid}/alerts/", params=params)

    def mark_alert_read(self, alert_id: int) -> Any:
        pid = self._require_project_id()
        return self._request(
            "POST",
            f"/api/projects/{pid}/alerts/{alert_id}/mark-as-read/",
        )

    def read_activity_log(
        self,
        *,
        action: str | None = None,
        actor_email: str | None = None,
        actor_type: str | None = None,
        created_after: str | None = None,
        created_before: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> Any:
        pid = self._require_project_id()
        return self._request(
            "GET",
            f"/api/projects/{pid}/activity-log/",
            params={
                "action": action,
                "actor_email": actor_email,
                "actor_type": actor_type,
                "created_after": created_after,
                "created_before": created_before,
                "page": page,
                "page_size": page_size,
            },
        )


def _drop_none(params: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in params.items() if v is not None}


def _extract_detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:200] or response.reason_phrase
    if isinstance(body, dict):
        for key in ("detail", "error", "message"):
            if key in body and isinstance(body[key], str):
                return body[key]
    return str(body)[:200]


def _header_or_none(response: httpx.Response, name: str) -> str | None:
    value = response.headers.get(name)
    return value or None
