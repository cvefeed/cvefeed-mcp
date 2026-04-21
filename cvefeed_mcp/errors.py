"""Structured error types surfaced to MCP clients.

Each error maps one HTTP failure mode from the CVEFeed REST API into a message
the calling agent can act on: missing/invalid token, scope denied, rate limited,
or transport failure. The MCP SDK turns raised exceptions into user-visible
tool errors, so message quality here determines how useful the agent's
fallback behavior is.
"""

from __future__ import annotations


class CvefeedError(Exception):
    """Base class for all cvefeed-mcp errors."""


class CvefeedAuthError(CvefeedError):
    """The configured CVEFEED_API_TOKEN is missing, invalid, or revoked."""


class CvefeedPermissionError(CvefeedError):
    """Request was authenticated but the token lacks the required scope or tier."""

    def __init__(self, message: str, *, required_scope: str | None = None, required_tier: str | None = None):
        super().__init__(message)
        self.required_scope = required_scope
        self.required_tier = required_tier


class CvefeedRateLimitError(CvefeedError):
    """Per-project rate limit bucket exhausted."""

    def __init__(self, message: str, *, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class CvefeedServerError(CvefeedError):
    """Upstream 5xx — the CVEFeed API failed to respond normally."""
