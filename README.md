# cvefeed-mcp

Model Context Protocol (MCP) server for the [CVEFeed.io](https://cvefeed.io) vulnerability intelligence API. Gives Claude Desktop, Cursor, Cline, and any other MCP-aware agent direct access to CVE search, project subscriptions, and vulnerability alerts.

## Install

```bash
pip install cvefeed-mcp
# or
uvx cvefeed-mcp
```

## Authenticate

Create a **Project API Token** at https://cvefeed.io/project/settings/api-tokens/, copy it, and export it alongside the numeric id of the project the token was issued for:

```bash
export CVEFEED_API_TOKEN=cvefeed_XXXXXXXX_...
export CVEFEED_PROJECT_ID=42
```

Each token is bound to exactly one project — one MCP install targets one project. The project id is the integer in your project dashboard URL (`/project/detail/<slug>/`; the numeric id is also shown in the project settings page).

### Recommended scopes for full MCP functionality

MCP tools span four resource scopes. Grant `read` on every resource the agent may touch so it doesn't hit an "insufficient scope" error mid-task:

- `vulnerabilities: read` — CVE / CPE / CVEQL / EPSS discovery tools
- `subscriptions: read` (or `write` to let the agent add / remove product subscriptions)
- `alerts: read` (or `write` to let the agent mark alerts as read)
- `activity_log: read` — Enterprise only; required by `read_project_activity_log`

`write` implies `read`, so you don't need to tick both on the same resource.

Optionally override the base URL for staging or self-hosted deployments:

```bash
export CVEFEED_BASE_URL=https://cvefeed.io   # default
```

## Use with Claude Desktop

Add to your `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or equivalent:

```json
{
  "mcpServers": {
    "cvefeed": {
      "command": "uvx",
      "args": ["cvefeed-mcp"],
      "env": {
        "CVEFEED_API_TOKEN": "cvefeed_XXXXXXXX_...",
        "CVEFEED_PROJECT_ID": "42"
      }
    }
  }
}
```

## Use with Cursor / Cline

Same MCP server config format — point `command` at `cvefeed-mcp` (or `uvx cvefeed-mcp`) and set `CVEFEED_API_TOKEN` + `CVEFEED_PROJECT_ID` in the env block.

## Available tools

| Tool                          | Purpose                                          | Auth required                   |
| ----------------------------- | ------------------------------------------------ | ------------------------------- |
| `search_cves`                 | Full-text and filter search over the CVE catalog | Optional                        |
| `get_cve_detail`              | Fetch full metadata for a single CVE             | Optional                        |
| `run_cveql_query`             | Execute a CVEQL query for advanced hunting       | Optional                        |
| `lookup_by_cpe`               | Resolve CPE 2.3 URIs to CVEs/products/vendors    | Pro tier                        |
| `get_exploit_intel`           | Public exploits and EPSS scores                  | Pro tier                        |
| `list_product_subscriptions`  | List subscriptions on the configured project     | `subscriptions:read`            |
| `add_product_subscription`    | Subscribe the project to a product               | `subscriptions:write`           |
| `remove_product_subscription` | Unsubscribe from a product                       | `subscriptions:write`           |
| `search_products`             | Search products with subscription status         | `subscriptions:read`            |
| `list_project_alerts`         | Read vulnerability alerts on the project         | `alerts:read`                   |
| `mark_alert_read`             | Mark an alert as read                            | `alerts:write`                  |
| `read_project_activity_log`   | Read project audit log                           | `activity_log:read`, Enterprise |

Every project-scoped tool targets the single project set via `CVEFEED_PROJECT_ID`; the LLM never passes a project id.

## Local development

```bash
cd mcp-server
pip install -e ".[dev]"
pytest -v
```

## Transport

Ships stdio transport only (what Claude Desktop, Cursor, and Cline expect). Remote streamable-HTTP transport may follow in a later release.

## License

MIT
