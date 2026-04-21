"""Shared test fixtures for cvefeed-mcp."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest

from cvefeed_mcp.client import CvefeedClient


@pytest.fixture
def mock_transport_factory() -> Callable[[Callable[[httpx.Request], httpx.Response]], httpx.MockTransport]:
    """Return a helper that wraps a request handler into an ``httpx.MockTransport``."""

    def _factory(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
        return httpx.MockTransport(handler)

    return _factory


@pytest.fixture
def make_client(
    mock_transport_factory: Callable[[Callable[[httpx.Request], httpx.Response]], httpx.MockTransport],
) -> Callable[..., CvefeedClient]:
    """Build a ``CvefeedClient`` backed by a user-supplied request handler."""

    def _make(
        handler: Callable[[httpx.Request], httpx.Response],
        *,
        token: str | None = "cvefeed_TEST1234_secretvalue",
        base_url: str = "https://api.test",
        project_id: int | None = 42,
    ) -> CvefeedClient:
        return CvefeedClient(
            base_url=base_url,
            token=token,
            project_id=project_id,
            transport=mock_transport_factory(handler),
        )

    return _make


def json_response(data: Any, *, status_code: int = 200, headers: dict[str, str] | None = None) -> httpx.Response:
    """Build a JSON ``httpx.Response`` for mock handlers."""
    return httpx.Response(status_code=status_code, json=data, headers=headers or {})
