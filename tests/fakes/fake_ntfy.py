"""In-memory ntfy mock for tests.

Captures every publish for inspection. Used by NtfyApprover tests to
verify the JSON payload + action URLs without needing a real ntfy
server.

Usage::

    fake = FakeNtfy(server="https://ntfy.test")
    client = httpx.AsyncClient(transport=fake.transport)
    approver = NtfyApprover(http_client=client, ntfy_server="https://ntfy.test", ...)

    # After approver.request_approval was called:
    assert len(fake.publishes) == 1
    publish = fake.publishes[0]
    assert publish["title"] == "[ironclaw] tool?"
    # Tap the Approve button:
    approve_action = next(a for a in publish["actions"] if a["label"] == "Approve")
    # Use approve_action["url"] and approve_action["body"] to call /hitl/ack.
"""

from __future__ import annotations

import json as _json
from typing import Any

import httpx


class FakeNtfy:
    """Minimal ntfy publish endpoint as an httpx MockTransport handler."""

    def __init__(
        self,
        *,
        server: str = "https://ntfy.test",
        require_auth_token: str | None = None,
    ) -> None:
        self._server = server.rstrip("/")
        self._require_auth_token = require_auth_token
        self.publishes: list[dict[str, Any]] = []
        # Failure injection.
        self._fail_next_n: int = 0

    def fail_next(self, n: int = 1) -> None:
        """Cause the next ``n`` publishes to return 503."""
        self._fail_next_n += n

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handler)

    def _handler(self, request: httpx.Request) -> httpx.Response:
        # ntfy publish: POST to the server root with JSON body
        # `{topic, title, message, actions, ...}`.
        if request.method != "POST" or str(request.url).rstrip("/") != self._server:
            return httpx.Response(404, text=f"unhandled {request.method} {request.url}")

        if self._fail_next_n > 0:
            self._fail_next_n -= 1
            return httpx.Response(503, text="injected ntfy failure")

        if self._require_auth_token is not None:
            authz = request.headers.get("Authorization", "")
            expected = f"Bearer {self._require_auth_token}"
            if authz != expected:
                return httpx.Response(401, text="unauthorized")

        try:
            body = _json.loads(request.content.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return httpx.Response(400, text="bad json")

        if not isinstance(body, dict):
            return httpx.Response(400, text="body must be object")

        self.publishes.append(body)
        return httpx.Response(200, json={"id": "fake-msg-id"})
