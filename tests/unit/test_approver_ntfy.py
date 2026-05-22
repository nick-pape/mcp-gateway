"""Tests for NtfyApprover (Phase 7).

Covers all the security-critical findings called out in the plan:

- Approve, reject, timeout flows
- Bogus ack_token in webhook -> ignored, always 200 (no oracle)
- Replay of consumed ack_token within TTL -> ignored
- Constant-time ack_token comparison
- Per-identity rate limit (5 pending)
- Webhook with no in-flight pending -> 200 (no oracle)
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from mcp_hub.approvers.ntfy import NtfyApprover
from mcp_hub.approvers.store import InMemoryTransientStore
from mcp_hub.bao_client import BaoClient
from mcp_hub.interfaces import ApprovalRequest, ApprovalResult, Approver
from tests.fakes.fake_bao import FakeBao
from tests.fakes.fake_ntfy import FakeNtfy

BAO_ADDR = "https://bao.test"
NTFY_SERVER = "https://ntfy.test"
WEBHOOK_BASE = "https://mcp.pape.house"
BAO_ROLE = "mcp-hitl"


@pytest.fixture
def jwt_file(tmp_path: Path) -> Path:
    p = tmp_path / "fanout_jwt"
    p.write_text("test-jwt")
    return p


@pytest.fixture
def publish_token_file(tmp_path: Path) -> Path:
    p = tmp_path / "ntfy-token"
    p.write_text("ntfy-publish-token")
    return p


@pytest.fixture
def fake_bao() -> FakeBao:
    return FakeBao(
        expected_jwt="test-jwt",
        role_to_token={BAO_ROLE: "tok-hitl"},
    )


@pytest.fixture
def fake_ntfy() -> FakeNtfy:
    return FakeNtfy(server=NTFY_SERVER, require_auth_token="ntfy-publish-token")


@pytest.fixture
def approver(
    fake_bao: FakeBao,
    fake_ntfy: FakeNtfy,
    jwt_file: Path,
    publish_token_file: Path,
) -> NtfyApprover:
    bao = BaoClient(
        addr=BAO_ADDR,
        jwt_path=jwt_file,
        http_client=httpx.AsyncClient(transport=fake_bao.transport),
    )
    return NtfyApprover(
        bao_client=bao,
        bao_role=BAO_ROLE,
        ntfy_server=NTFY_SERVER,
        topic_template="mcp-hitl-approvals",
        publish_token_path=publish_token_file,
        webhook_base_url=WEBHOOK_BASE,
        rate_limit_per_identity=5,
        http_client=httpx.AsyncClient(transport=fake_ntfy.transport),
    )


def _request(
    identity: str = "ironclaw",
    tool: str = "technitium_dns_delete_record",
) -> ApprovalRequest:
    return ApprovalRequest(
        request_id="01HXY00000000000000000000",
        identity=identity,
        mcp_name=tool.split("_", 1)[0],
        tool=tool,
        justification="user explicitly asked to remove the stale record",
        args={"domain": "stale.pape.house"},
        args_summary="domain=stale.pape.house",
    )


# Helper: extract the nonce + ack_token from the most-recent ntfy publish.
def _last_publish_secrets(fake_ntfy: FakeNtfy) -> tuple[str, str, str, str]:
    publish = fake_ntfy.publishes[-1]
    actions = publish["actions"]
    approve = next(a for a in actions if a["label"] == "Approve")
    reject = next(a for a in actions if a["label"] == "Reject")
    nonce = parse_qs(urlparse(approve["url"]).query)["nonce"][0]
    ack_token = json.loads(approve["body"])["ack_token"]
    return nonce, ack_token, approve["body"], reject["body"]


# ---------------------------------------------------------------------------
# Protocol conformance + construction
# ---------------------------------------------------------------------------


def test_satisfies_approver_protocol(approver: NtfyApprover) -> None:
    assert isinstance(approver, Approver)
    assert approver.name == "ntfy"


async def test_works_with_in_memory_store_no_bao(
    fake_ntfy: FakeNtfy, publish_token_file: Path
) -> None:
    """End-to-end approve cycle with InMemoryTransientStore — no bao at all."""
    approver = NtfyApprover(
        store=InMemoryTransientStore(),
        ntfy_server=NTFY_SERVER,
        topic_template="mcp-hitl-approvals",
        publish_token_path=publish_token_file,
        webhook_base_url=WEBHOOK_BASE,
        http_client=httpx.AsyncClient(transport=fake_ntfy.transport),
    )
    task = asyncio.create_task(approver.request_approval(_request(), timeout_s=5.0))
    await asyncio.sleep(0.05)  # let it stage + publish
    nonce, _ack, approve_body, _reject = _last_publish_secrets(fake_ntfy)
    status = await approver.handle_webhook(nonce=nonce, body=json.loads(approve_body))
    assert status == 200
    assert await task == ApprovalResult.APPROVED
    await approver.close()


def test_rejects_non_http_ntfy_server(jwt_file: Path, publish_token_file: Path) -> None:
    bao = BaoClient(addr=BAO_ADDR, jwt_path=jwt_file)
    with pytest.raises(ValueError, match="ntfy_server must be http"):
        NtfyApprover(
            bao_client=bao,
            bao_role=BAO_ROLE,
            ntfy_server="ftp://nope",
            topic_template="x",
            publish_token_path=publish_token_file,
            webhook_base_url=WEBHOOK_BASE,
        )


def test_rejects_non_http_webhook_base(jwt_file: Path, publish_token_file: Path) -> None:
    bao = BaoClient(addr=BAO_ADDR, jwt_path=jwt_file)
    with pytest.raises(ValueError, match="webhook_base_url must be http"):
        NtfyApprover(
            bao_client=bao,
            bao_role=BAO_ROLE,
            ntfy_server=NTFY_SERVER,
            topic_template="x",
            publish_token_path=publish_token_file,
            webhook_base_url="ftp://nope",
        )


def test_rejects_unknown_template_placeholder(
    jwt_file: Path, publish_token_file: Path
) -> None:
    bao = BaoClient(addr=BAO_ADDR, jwt_path=jwt_file)
    with pytest.raises(ValueError, match="unsupported placeholder"):
        NtfyApprover(
            bao_client=bao,
            bao_role=BAO_ROLE,
            ntfy_server=NTFY_SERVER,
            topic_template="mcp-{user}-hitl",  # {user} not recognized
            publish_token_path=publish_token_file,
            webhook_base_url=WEBHOOK_BASE,
        )


async def test_topic_template_substitutes_identity(
    approver: NtfyApprover, fake_ntfy: FakeNtfy
) -> None:
    """A {identity} placeholder in topic_template resolves per-call."""
    # Hot-swap to a templated topic — unit test scope, private attr is
    # fine. Production paths set this at construction via factory.py.
    approver._topic_template = "mcp-hitl-{identity}"

    async def tap() -> None:
        await asyncio.sleep(0.05)
        nonce, _ack, approve_body, _rej = _last_publish_secrets(fake_ntfy)
        await approver.handle_webhook(nonce=nonce, body=json.loads(approve_body))

    # First call: identity=ironclaw → topic mcp-hitl-ironclaw
    task = asyncio.create_task(tap())
    decision = await approver.request_approval(_request(identity="ironclaw"), timeout_s=5.0)
    await task
    assert decision == ApprovalResult.APPROVED
    assert fake_ntfy.publishes[-1]["topic"] == "mcp-hitl-ironclaw"

    # Second call: identity=paperless-bot → topic mcp-hitl-paperless-bot
    fake_ntfy.publishes.clear()
    task2 = asyncio.create_task(tap())
    await approver.request_approval(_request(identity="paperless-bot"), timeout_s=5.0)
    await task2
    assert fake_ntfy.publishes[-1]["topic"] == "mcp-hitl-paperless-bot"


async def test_static_topic_no_placeholder_is_unchanged(
    approver: NtfyApprover, fake_ntfy: FakeNtfy
) -> None:
    """A static topic_template (no {identity}) ignores the request identity."""
    # The default fixture uses static "mcp-hitl-approvals" — no template.
    async def tap() -> None:
        await asyncio.sleep(0.05)
        nonce, _ack, approve_body, _rej = _last_publish_secrets(fake_ntfy)
        await approver.handle_webhook(nonce=nonce, body=json.loads(approve_body))

    task = asyncio.create_task(tap())
    await approver.request_approval(_request(identity="ironclaw"), timeout_s=5.0)
    await task
    assert fake_ntfy.publishes[-1]["topic"] == "mcp-hitl-approvals"

    fake_ntfy.publishes.clear()
    task2 = asyncio.create_task(tap())
    await approver.request_approval(_request(identity="paperless-bot"), timeout_s=5.0)
    await task2
    assert fake_ntfy.publishes[-1]["topic"] == "mcp-hitl-approvals"


# ---------------------------------------------------------------------------
# Happy path: approve + reject + timeout
# ---------------------------------------------------------------------------


async def test_approve_flow_returns_approved(
    approver: NtfyApprover, fake_ntfy: FakeNtfy
) -> None:
    request = _request()

    async def driver() -> None:
        # Wait briefly for ntfy publish to land, then "tap Approve".
        await asyncio.sleep(0.05)
        nonce, _ack_token, approve_body, _reject_body = _last_publish_secrets(fake_ntfy)
        result = await approver.handle_webhook(nonce=nonce, body=json.loads(approve_body))
        assert result == 200

    driver_task = asyncio.create_task(driver())
    decision = await approver.request_approval(request, timeout_s=5.0)
    await driver_task
    assert decision == ApprovalResult.APPROVED
    await approver.close()


async def test_reject_flow_returns_rejected(
    approver: NtfyApprover, fake_ntfy: FakeNtfy
) -> None:
    request = _request()

    async def driver() -> None:
        await asyncio.sleep(0.05)
        nonce, _ack_token, _approve_body, reject_body = _last_publish_secrets(fake_ntfy)
        await approver.handle_webhook(nonce=nonce, body=json.loads(reject_body))

    driver_task = asyncio.create_task(driver())
    decision = await approver.request_approval(request, timeout_s=5.0)
    await driver_task
    assert decision == ApprovalResult.REJECTED
    await approver.close()


async def test_timeout_returns_timeout(approver: NtfyApprover) -> None:
    request = _request()
    decision = await approver.request_approval(request, timeout_s=0.1)
    assert decision == ApprovalResult.TIMEOUT
    await approver.close()


# ---------------------------------------------------------------------------
# Webhook security: always-200, no oracle
# ---------------------------------------------------------------------------


async def test_webhook_with_unknown_nonce_returns_200(approver: NtfyApprover) -> None:
    """An unknown nonce gets 200, not 404 — no oracle for attackers."""
    result = await approver.handle_webhook(
        nonce="never-seen-this-nonce-before",
        body={"ack_token": "any", "decision": "approve"},
    )
    assert result == 200
    await approver.close()


async def test_webhook_with_bogus_ack_token_returns_200_and_ignored(
    approver: NtfyApprover, fake_ntfy: FakeNtfy
) -> None:
    """Wrong ack_token must NOT signal the pending event, but webhook 200s."""
    request = _request()
    started = asyncio.Event()
    decision_holder: list[ApprovalResult] = []

    async def caller() -> None:
        started.set()
        d = await approver.request_approval(request, timeout_s=0.5)
        decision_holder.append(d)

    caller_task = asyncio.create_task(caller())
    await started.wait()
    await asyncio.sleep(0.05)  # let publish happen

    nonce, _real_ack, _approve_body, _reject_body = _last_publish_secrets(fake_ntfy)
    # Attacker posts wrong ack_token.
    result = await approver.handle_webhook(
        nonce=nonce,
        body={"ack_token": "WRONG-TOKEN", "decision": "approve"},
    )
    assert result == 200
    # The legit caller should still time out — bogus ack didn't signal.
    await caller_task
    assert decision_holder == [ApprovalResult.TIMEOUT]
    await approver.close()


async def test_webhook_with_malformed_body_returns_200(approver: NtfyApprover) -> None:
    """Bodies missing decision / ack_token still 200, ignored."""
    result = await approver.handle_webhook(nonce="x", body={"random": "junk"})
    assert result == 200
    result = await approver.handle_webhook(
        nonce="x", body={"ack_token": "x", "decision": "MAYBE"}
    )
    assert result == 200
    await approver.close()


async def test_webhook_replay_after_consumed_is_ignored(
    approver: NtfyApprover, fake_ntfy: FakeNtfy
) -> None:
    """An ack_token consumed once cannot be replayed within TTL."""
    request = _request()

    async def driver() -> None:
        await asyncio.sleep(0.05)
        nonce, _ack, approve_body, _reject = _last_publish_secrets(fake_ntfy)
        # First tap: legitimate.
        await approver.handle_webhook(nonce=nonce, body=json.loads(approve_body))
        # Replay (within TTL): bao entry already deleted -> webhook 200s
        # but does nothing.
        result2 = await approver.handle_webhook(
            nonce=nonce, body=json.loads(approve_body)
        )
        assert result2 == 200

    driver_task = asyncio.create_task(driver())
    decision = await approver.request_approval(request, timeout_s=5.0)
    await driver_task
    assert decision == ApprovalResult.APPROVED  # only the first tap counted
    await approver.close()


# ---------------------------------------------------------------------------
# Per-identity rate limit
# ---------------------------------------------------------------------------


async def test_per_identity_rate_limit(approver: NtfyApprover) -> None:
    """6th concurrent push-approve from same identity is rejected immediately."""
    request = _request(identity="ironclaw")

    # Fire 5 long-running approvals; they'll all wait for ntfy taps that
    # never come (timeout=10s).
    long_tasks = [
        asyncio.create_task(approver.request_approval(request, timeout_s=10.0))
        for _ in range(5)
    ]
    # Let them register.
    await asyncio.sleep(0.05)
    # 6th must reject immediately without a publish.
    sixth = await approver.request_approval(request, timeout_s=10.0)
    assert sixth == ApprovalResult.REJECTED

    # Cancel the long ones so the test doesn't hang.
    for t in long_tasks:
        t.cancel()
    for t in long_tasks:
        try:
            await t
        except asyncio.CancelledError:
            pass
    await approver.close()


async def test_rate_limit_separate_per_identity(approver: NtfyApprover) -> None:
    """ironclaw at limit doesn't affect paperless-bot."""
    iron_req = _request(identity="ironclaw")
    paper_req = _request(identity="paperless-bot")

    iron_tasks = [
        asyncio.create_task(approver.request_approval(iron_req, timeout_s=10.0))
        for _ in range(5)
    ]
    await asyncio.sleep(0.05)

    # paperless-bot still has 5 slots.
    paper_decision = asyncio.create_task(
        approver.request_approval(paper_req, timeout_s=0.1)
    )
    # paper request will time out (no one taps), but it shouldn't be
    # rejected by the rate limiter.
    result = await paper_decision
    assert result == ApprovalResult.TIMEOUT  # not REJECTED

    for t in iron_tasks:
        t.cancel()
    for t in iron_tasks:
        try:
            await t
        except asyncio.CancelledError:
            pass
    await approver.close()


# ---------------------------------------------------------------------------
# Publish payload shape
# ---------------------------------------------------------------------------


async def test_publish_payload_includes_required_fields(
    approver: NtfyApprover, fake_ntfy: FakeNtfy
) -> None:
    request = _request()
    # Time out fast; we just want to inspect the publish.
    await approver.request_approval(request, timeout_s=0.1)
    assert len(fake_ntfy.publishes) == 1
    publish = fake_ntfy.publishes[0]
    assert publish["topic"] == "mcp-hitl-approvals"
    assert "ironclaw" in publish["title"]
    # ntfy.py strips the mcp-name prefix, so the title reads
    # "<id> wants to run technitium dns_delete_record" — assert both parts.
    assert "technitium" in publish["title"]
    assert "dns_delete_record" in publish["title"]
    labels = {a["label"] for a in publish["actions"]}
    assert labels == {"Approve", "Reject"}
    # Both actions POST to the configured webhook.
    for a in publish["actions"]:
        assert a["url"].startswith(f"{WEBHOOK_BASE}/hitl/ack?nonce=")
        assert a["method"] == "POST"
    await approver.close()


async def test_publish_failure_returns_rejected(
    approver: NtfyApprover, fake_ntfy: FakeNtfy
) -> None:
    """If ntfy itself rejects the publish, we fail closed (not hang)."""
    fake_ntfy.fail_next(1)
    request = _request()
    decision = await approver.request_approval(request, timeout_s=5.0)
    assert decision == ApprovalResult.REJECTED
    await approver.close()


# ---------------------------------------------------------------------------
# Constant-time compare lock-in
# ---------------------------------------------------------------------------


def test_constant_time_compare_used_for_ack_validation() -> None:
    """The compare_digest helper is the function used in ntfy.py.

    This test guards against future refactors that switch to ``==``.
    """
    import inspect

    from mcp_hub.approvers import ntfy as ntfy_module
    from mcp_hub.bao_client import compare_digest

    src = inspect.getsource(ntfy_module)
    # Either the helper name appears, or its underlying secrets.compare_digest.
    # Both are constant-time. Plain `==` on str is NOT.
    assert "compare_digest" in src
    assert compare_digest("a" * 32, "a" * 32) is True
    assert compare_digest("a" * 32, "b" * 32) is False
