"""FastMCP server definition — wires each MCP tool to a :class:`CvefeedClient` method.

Tool names and capability boundaries mirror the SKILL.md slugs published at
``/.well-known/agent-skills/index.json`` so agents can discover the same
surface through either channel. Each tool's docstring becomes the tool
description surfaced to the LLM; keep them action-oriented.
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from cvefeed_mcp.client import CvefeedClient


def build_server(client: CvefeedClient | None = None) -> FastMCP:
    """Construct a FastMCP server bound to a CVEFeed REST client.

    A real ``cvefeed-mcp`` process calls this with no arguments and the client
    picks up ``CVEFEED_API_TOKEN`` / ``CVEFEED_BASE_URL`` from the environment.
    Tests pass an injected client wired to an ``httpx.MockTransport``.
    """

    mcp = FastMCP(
        "cvefeed-mcp",
        instructions=(
            "Query CVEFeed.io vulnerability intelligence: search CVEs, resolve "
            "CPEs, read EPSS and exploit data, and manage project-scoped "
            "subscriptions and alerts. All project-scoped tools target the "
            "project configured via CVEFEED_PROJECT_ID and authenticate with "
            "CVEFEED_API_TOKEN; the LLM does not supply a project id."
        ),
    )
    api = client or CvefeedClient()

    # ------------------------------------------------------------------
    # Vulnerability discovery (global, scope: vulnerabilities:read)
    # ------------------------------------------------------------------
    @mcp.tool()
    def search_cves(
        query: Annotated[
            str | None,
            Field(description="Free-text query matched against CVE id, title, description"),
        ] = None,
        severity: Annotated[
            str | None,
            Field(description="One of: critical, high, medium, low"),
        ] = None,
        cvss_min: Annotated[float | None, Field(ge=0, le=10)] = None,
        cvss_max: Annotated[float | None, Field(ge=0, le=10)] = None,
        published_after: Annotated[
            str | None,
            Field(description="ISO 8601 date lower bound, e.g. 2026-01-01"),
        ] = None,
        published_before: Annotated[str | None, Field(description="ISO 8601 date upper bound")] = None,
        vendor: Annotated[str | None, Field(description="Vendor slug")] = None,
        product: Annotated[str | None, Field(description="Product slug")] = None,
        page: Annotated[int | None, Field(ge=1)] = None,
        page_size: Annotated[int | None, Field(ge=1, le=100)] = None,
    ) -> dict[str, Any]:
        """Search the CVEFeed catalog with keyword and filter parameters.

        Returns a paginated DRF response with ``count``, ``next``, ``previous``,
        and ``results`` — each result is a CVE summary.
        """
        return api.search_cves(
            query=query,
            severity=severity,
            cvss_min=cvss_min,
            cvss_max=cvss_max,
            published_after=published_after,
            published_before=published_before,
            vendor=vendor,
            product=product,
            page=page,
            page_size=page_size,
        )

    @mcp.tool()
    def get_cve_detail(
        cve_id: Annotated[
            str,
            Field(
                description="CVE identifier, e.g. CVE-2026-12345",
                pattern=r"^CVE-\d{4}-\d{4,}$",
            ),
        ],
        include_change_history: Annotated[
            bool,
            Field(description="Also fetch the CVE change history"),
        ] = False,
    ) -> dict[str, Any]:
        """Fetch full metadata for a single CVE.

        Returns CVSS, EPSS-adjacent scoring, affected products, CWE mapping,
        CISA KEV state, and references. When ``include_change_history`` is true
        the response is ``{"detail": ..., "change_history": [...]}``.
        """
        detail = api.get_cve(cve_id)
        if not include_change_history:
            return detail
        return {
            "detail": detail,
            "change_history": api.get_cve_change_history(cve_id),
        }

    @mcp.tool()
    def run_cveql_query(
        query: Annotated[
            str,
            Field(description="CVEQL expression, e.g. 'severity:critical AND vendor:microsoft'"),
        ],
        page: Annotated[int | None, Field(ge=1)] = None,
        validate_only: Annotated[
            bool,
            Field(description="If true, validate the syntax without executing"),
        ] = False,
    ) -> dict[str, Any]:
        """Execute (or validate) a CVEQL threat-hunting query.

        Use ``validate_only=true`` during interactive query construction to get
        parse errors without spending a search-class request.
        """
        if validate_only:
            return api.cveql_validate(query)
        return api.cveql_search(query, page=page)

    @mcp.tool()
    def cveql_schema() -> dict[str, Any]:
        """Return the CVEQL schema (fields, operators, value types).

        Call this once before constructing a CVEQL query so the agent knows
        which fields are available and how they're typed.
        """
        return api.cveql_introspect()

    @mcp.tool()
    def lookup_by_cpe(
        cpe: Annotated[
            str,
            Field(description="CPE 2.3 URI, e.g. cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"),
        ],
        include: Annotated[
            list[str] | None,
            Field(
                description="Subset of {'cves','products','vendors'} to fetch. Defaults to all three.",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Resolve a CPE 2.3 URI to matching CVEs, products, and vendors.

        Requires Pro tier or above. Each entry in the ``include`` list runs one
        upstream request, so narrow it when latency matters.
        """
        kinds = set(include) if include else {"cves", "products", "vendors"}
        result: dict[str, Any] = {}
        if "cves" in kinds:
            result["cves"] = api.vulnerabilities_by_cpe(cpe)
        if "products" in kinds:
            result["products"] = api.products_by_cpe(cpe)
        if "vendors" in kinds:
            result["vendors"] = api.vendors_by_cpe(cpe)
        return result

    @mcp.tool()
    def get_exploit_intel(
        cve_id: Annotated[str | None, Field(description="Limit results to this CVE")] = None,
        include_epss: Annotated[bool, Field(description="Include EPSS score alongside exploit repos")] = True,
        page: Annotated[int | None, Field(ge=1)] = None,
    ) -> dict[str, Any]:
        """Retrieve public exploits and, optionally, the EPSS score for a CVE.

        Requires Pro tier or above.
        """
        result: dict[str, Any] = {"exploits": api.list_exploit_intel(cve_id=cve_id, page=page)}
        if include_epss:
            result["epss"] = api.get_epss(cve_id=cve_id)
        return result

    # ------------------------------------------------------------------
    # Project subscriptions (scope: subscriptions:{read,write})
    #
    # All project-scoped tools target the project configured via
    # CVEFEED_PROJECT_ID; the LLM never supplies an id.
    # ------------------------------------------------------------------
    @mcp.tool()
    def list_product_subscriptions() -> dict[str, Any]:
        """List product subscriptions on the configured CVEFeed project.

        Requires scope ``subscriptions:read`` on the configured API token.
        """
        return api.list_subscriptions()

    @mcp.tool()
    def add_product_subscription(
        product_ids: Annotated[
            list[int],
            Field(description="Product ids to subscribe to, as integers"),
        ],
    ) -> dict[str, Any]:
        """Subscribe the configured project to one or more products.

        Requires scope ``subscriptions:write``. Subscriptions count against the
        owner's tier limit across all their projects; a 403 from this call is
        usually a tier limit, not a permission problem.
        """
        return api.add_subscriptions(product_ids)

    @mcp.tool()
    def remove_product_subscription(
        product_ids: Annotated[list[int], Field(description="Product ids to unsubscribe from")],
    ) -> dict[str, Any]:
        """Unsubscribe the configured project from one or more products.

        Requires scope ``subscriptions:write``.
        """
        return api.remove_subscriptions(product_ids)

    @mcp.tool()
    def search_products(
        query: Annotated[str, Field(min_length=1, description="Vendor or product name fragment")],
        page: Annotated[int | None, Field(ge=1)] = None,
    ) -> dict[str, Any]:
        """Search products with subscription status flagged per result.

        Use this before ``add_product_subscription`` to get the product id and
        to check whether the configured project is already subscribed.
        """
        return api.search_products(query=query, page=page)

    # ------------------------------------------------------------------
    # Project alerts (scope: alerts:{read,write})
    # ------------------------------------------------------------------
    @mcp.tool()
    def list_project_alerts(
        unread_only: Annotated[bool, Field(description="Return only unread alerts")] = False,
        page: Annotated[int | None, Field(ge=1)] = None,
        page_size: Annotated[int | None, Field(ge=1, le=100)] = None,
    ) -> dict[str, Any]:
        """List vulnerability alerts raised on the configured CVEFeed project.

        Requires scope ``alerts:read``.
        """
        return api.list_alerts(
            is_read=False if unread_only else None,
            page=page,
            page_size=page_size,
        )

    @mcp.tool()
    def mark_alert_read(
        alert_id: Annotated[int, Field(description="Alert id to mark as read")],
    ) -> dict[str, Any]:
        """Mark a single alert on the configured project as read.

        Idempotent. Requires scope ``alerts:write``.
        """
        return api.mark_alert_read(alert_id) or {"ok": True}

    # ------------------------------------------------------------------
    # Activity log (Enterprise, scope: activity_log:read)
    # ------------------------------------------------------------------
    @mcp.tool()
    def read_project_activity_log(
        action: Annotated[
            str | None,
            Field(description="Filter by action type, e.g. 'subscription.created'"),
        ] = None,
        actor_email: Annotated[str | None, Field(description="Filter by actor email")] = None,
        actor_type: Annotated[
            str | None,
            Field(description="One of: user, api_token, system"),
        ] = None,
        created_after: Annotated[str | None, Field(description="ISO 8601 datetime floor")] = None,
        created_before: Annotated[str | None, Field(description="ISO 8601 datetime ceiling")] = None,
        page: Annotated[int | None, Field(ge=1)] = None,
        page_size: Annotated[int | None, Field(ge=1, le=100)] = None,
    ) -> dict[str, Any]:
        """Read the configured project's audit log.

        Enterprise tier only; requires scope ``activity_log:read``.
        """
        return api.read_activity_log(
            action=action,
            actor_email=actor_email,
            actor_type=actor_type,
            created_after=created_after,
            created_before=created_before,
            page=page,
            page_size=page_size,
        )

    return mcp
