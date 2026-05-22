"""Tests for the policy loader.

Covers schema validation, cross-field invariants, and the
locked-in HITL precedence rule (longest pattern wins, ties = dict order).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mcp_hub.policy import (
    HITLAction,
    HubConfig,
    IdentityPolicy,
    Policy,
    PolicyError,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_POLICY = REPO_ROOT / "policy.example.yaml"


# ---------------------------------------------------------------------------
# Minimal valid policy (used as a base; tests mutate copies)
# ---------------------------------------------------------------------------


MINIMAL: dict[str, object] = {
    "version": 1,
    "auth": {
        "issuer": "https://auth.test/",
        "jwks_uri": "https://auth.test/jwks",
        "audience_prefix": "mcp-",
    },
    "secret_backend": {"name": "env"},
    "approver": {"name": "auto"},
    "mcps": {
        "technitium": {
            "command": ["node", "/app/index.js"],
            "secret_env_name": "TECHNITIUM_TOKEN_FILE",
        },
    },
    "identities": {
        "ironclaw": {
            "aud": "mcp-ironclaw",
            "uid_base": 1001,
            "allowed_tools": ["technitium_dns_*"],
            "hitl": {"defaults": "auto-approve"},
            "secrets": {
                "technitium": {
                    "path": "secret/data/x",
                    "field": "api_token",
                },
            },
        },
    },
}


def test_identity_policy_secrets_optional() -> None:
    """#18: an identity that needs no per-MCP secret entry may omit `secrets`."""
    p = IdentityPolicy(aud="mcp-x", uid_base=1001, allowed_tools=["outline_*"])
    assert p.secrets == {}


def test_container_host_rejected_on_stdio() -> None:
    """#16: `container_host` is container-transport only."""
    import copy

    from pydantic import ValidationError

    raw = copy.deepcopy(MINIMAL)
    raw["mcps"]["technitium"]["container_host"] = "host.docker.internal"  # type: ignore[index]
    with pytest.raises(ValidationError, match="container-only"):
        HubConfig.model_validate(raw)


def _policy(overrides: dict[str, object] | None = None) -> Policy:
    """Build a Policy from MINIMAL with optional overrides merged in."""
    import copy

    raw = copy.deepcopy(MINIMAL)
    if overrides:
        for key, val in overrides.items():
            raw[key] = val
    return Policy(HubConfig.model_validate(raw))


# ---------------------------------------------------------------------------
# Schema basics
# ---------------------------------------------------------------------------


def test_minimal_policy_loads() -> None:
    policy = _policy()
    assert policy.config.version == 1
    assert "ironclaw" in policy.config.identities


def test_unsupported_version_rejected() -> None:
    raw = {**MINIMAL, "version": 2}
    with pytest.raises(Exception, match="unsupported policy version"):
        HubConfig.model_validate(raw)


def test_extra_keys_at_top_level_rejected() -> None:
    raw = {**MINIMAL, "unknown_field": True}
    with pytest.raises(Exception):
        HubConfig.model_validate(raw)


def test_example_policy_loads_cleanly() -> None:
    """The shipped example must always validate; it documents the schema."""
    policy = Policy.from_yaml(EXAMPLE_POLICY)
    assert "ironclaw" in policy.config.identities
    assert "technitium" in policy.config.mcps


# ---------------------------------------------------------------------------
# YAML loading errors
# ---------------------------------------------------------------------------


def test_from_yaml_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read"):
        Policy.from_yaml(tmp_path / "nonexistent.yaml")


def test_from_yaml_bad_yaml(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: [valid: yaml")
    with pytest.raises(PolicyError, match="YAML parse error"):
        Policy.from_yaml(bad)


def test_from_yaml_top_level_not_mapping(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- 1\n- 2\n")
    with pytest.raises(PolicyError, match="top level must be a mapping"):
        Policy.from_yaml(bad)


def test_from_yaml_schema_error(tmp_path: Path) -> None:
    """Raised PolicyError wraps the pydantic ValidationError detail."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"version": 1}))  # missing required fields
    with pytest.raises(PolicyError, match="schema validation failed"):
        Policy.from_yaml(bad)


# ---------------------------------------------------------------------------
# MCP name validation
# ---------------------------------------------------------------------------


def test_mcp_name_with_underscore_rejected() -> None:
    raw = {**MINIMAL, "mcps": {"paperless_gpt": MINIMAL["mcps"]["technitium"]}}  # type: ignore[index]
    with pytest.raises(Exception, match="must not contain '_'"):
        HubConfig.model_validate(raw)


def test_mcp_name_empty_rejected() -> None:
    raw = {**MINIMAL, "mcps": {"": MINIMAL["mcps"]["technitium"]}}  # type: ignore[index]
    with pytest.raises(Exception, match="must be non-empty"):
        HubConfig.model_validate(raw)


# ---------------------------------------------------------------------------
# Cross-field invariants
# ---------------------------------------------------------------------------


def test_identity_secrets_for_unknown_mcp_rejected() -> None:
    """An identity can't have a secret for an MCP that isn't registered."""
    import copy

    raw = copy.deepcopy(MINIMAL)
    identity = raw["identities"]["ironclaw"]  # type: ignore[index]
    identity["secrets"]["nonexistent"] = {
        "path": "x",
        "field": "y",
    }
    with pytest.raises(PolicyError, match="unknown MCPs"):
        Policy(HubConfig.model_validate(raw))


def test_allowed_tools_glob_with_unknown_mcp_prefix_rejected() -> None:
    """allowed_tools entry must start with a known MCP name."""
    import copy

    raw = copy.deepcopy(MINIMAL)
    raw["identities"]["ironclaw"]["allowed_tools"] = ["nonexistent_*"]  # type: ignore[index]
    with pytest.raises(PolicyError, match="doesn't start with any known MCP"):
        Policy(HubConfig.model_validate(raw))


# ---------------------------------------------------------------------------
# Tool curation
# ---------------------------------------------------------------------------


def test_is_tool_allowed_simple_glob() -> None:
    policy = _policy()
    assert policy.is_tool_allowed("ironclaw", "technitium_dns_list") is True
    assert policy.is_tool_allowed("ironclaw", "technitium_dhcp_list") is False


def test_filter_tools_returns_only_allowed() -> None:
    policy = _policy()
    all_tools = [
        "technitium_dns_list",
        "technitium_dns_delete_record",
        "technitium_dhcp_list_reservations",
        "paperless_get_doc",
    ]
    assert policy.filter_tools("ironclaw", all_tools) == [
        "technitium_dns_list",
        "technitium_dns_delete_record",
    ]


def test_unknown_identity_raises() -> None:
    policy = _policy()
    with pytest.raises(PolicyError, match="unknown identity"):
        policy.identity("nobody")


def test_identity_for_audience_returns_match_or_none() -> None:
    policy = _policy()
    assert policy.identity_for_audience("mcp-ironclaw") == "ironclaw"
    assert policy.identity_for_audience("mcp-nobody") is None


# ---------------------------------------------------------------------------
# HITL precedence — the locked-in rule
# ---------------------------------------------------------------------------


def _hitl_policy(overrides: dict[str, str]) -> Policy:
    """Build a policy with custom HITL overrides for ironclaw."""
    import copy

    raw = copy.deepcopy(MINIMAL)
    raw["identities"]["ironclaw"]["allowed_tools"] = ["technitium_*"]  # type: ignore[index]
    raw["identities"]["ironclaw"]["hitl"] = {  # type: ignore[index]
        "defaults": "auto-approve",
        "overrides": overrides,
    }
    return Policy(HubConfig.model_validate(raw))


def test_hitl_no_overrides_uses_defaults() -> None:
    policy = _hitl_policy({})
    assert policy.hitl_decision("ironclaw", "technitium_dns_list") == HITLAction.AUTO_APPROVE


def test_hitl_exact_match_override_wins_over_defaults() -> None:
    policy = _hitl_policy({"technitium_dns_delete_record": "push-approve"})
    assert (
        policy.hitl_decision("ironclaw", "technitium_dns_delete_record")
        == HITLAction.PUSH_APPROVE
    )
    # Tools not matching the override fall through to defaults
    assert policy.hitl_decision("ironclaw", "technitium_dns_list") == HITLAction.AUTO_APPROVE


def test_hitl_glob_override_matches() -> None:
    policy = _hitl_policy({"technitium_dhcp_remove_*": "push-approve"})
    assert (
        policy.hitl_decision("ironclaw", "technitium_dhcp_remove_lease")
        == HITLAction.PUSH_APPROVE
    )


def test_hitl_longer_pattern_wins_over_shorter() -> None:
    """Most-specific (longest pattern) wins."""
    # Both match technitium_dns_delete_record; the longer pattern is more specific.
    policy = _hitl_policy(
        {
            "technitium_*": "auto-approve",  # short, matches everything
            "technitium_dns_delete_record": "push-approve",  # exact, longest
        }
    )
    assert (
        policy.hitl_decision("ironclaw", "technitium_dns_delete_record")
        == HITLAction.PUSH_APPROVE
    )
    # And short pattern still works for non-overlap tools:
    assert policy.hitl_decision("ironclaw", "technitium_dns_list") == HITLAction.AUTO_APPROVE


def test_hitl_glob_specificity_beats_other_glob() -> None:
    policy = _hitl_policy(
        {
            "technitium_*": "auto-approve",
            "technitium_dns_*": "push-approve",
        }
    )
    # technitium_dns_* is longer than technitium_* → wins on overlap
    assert (
        policy.hitl_decision("ironclaw", "technitium_dns_anything")
        == HITLAction.PUSH_APPROVE
    )
    # But things outside technitium_dns_* fall through to technitium_*
    assert (
        policy.hitl_decision("ironclaw", "technitium_dhcp_anything")
        == HITLAction.AUTO_APPROVE
    )


def test_hitl_tie_broken_by_insertion_order() -> None:
    """When two patterns of equal length both match, dict order wins."""
    # Use two patterns of identical length matching the same tool.
    policy = _hitl_policy(
        {
            "technitium_a*": "push-approve",
            "technitium_*a": "reject",  # same length: 12 chars
        }
    )
    # Both match "technitium_aaa". First in dict order ("technitium_a*") wins.
    assert (
        policy.hitl_decision("ironclaw", "technitium_aaa")
        == HITLAction.PUSH_APPROVE
    )


def test_hitl_unknown_value_rejected_at_load() -> None:
    """An override value that isn't one of the three known actions is rejected."""
    import copy

    raw = copy.deepcopy(MINIMAL)
    raw["identities"]["ironclaw"]["hitl"] = {  # type: ignore[index]
        "defaults": "auto-approve",
        "overrides": {"technitium_dns_list": "yolo"},  # not a valid action
    }
    with pytest.raises(Exception):
        HubConfig.model_validate(raw)


# ---------------------------------------------------------------------------
# Routing helper
# ---------------------------------------------------------------------------


def test_mcp_name_for_tool_splits_on_first_underscore() -> None:
    policy = _policy()
    assert policy.mcp_name_for_tool("technitium_dns_delete_record") == "technitium"
    assert policy.mcp_name_for_tool("paperless_get_doc") == "paperless"


def test_is_tool_ever_push_approved_returns_true_for_overrides() -> None:
    policy = _hitl_policy({"technitium_dns_delete_record": "push-approve"})
    assert policy.is_tool_ever_push_approved("technitium_dns_delete_record") is True
    # Non-matching tool: still defaults=auto-approve, so no.
    assert policy.is_tool_ever_push_approved("technitium_dns_list") is False


def test_is_tool_ever_push_approved_glob_match() -> None:
    policy = _hitl_policy({"technitium_*delete*": "push-approve"})
    assert policy.is_tool_ever_push_approved("technitium_dns_delete_record") is True
    assert policy.is_tool_ever_push_approved("technitium_zones_delete_zone") is True
    assert policy.is_tool_ever_push_approved("technitium_dns_list") is False


def test_is_tool_ever_push_approved_default_push_approve() -> None:
    """defaults=push-approve makes ALL tools require approval for that identity."""
    import copy

    raw = copy.deepcopy(MINIMAL)
    raw["identities"]["ironclaw"]["hitl"] = {"defaults": "push-approve"}  # type: ignore[index]
    policy = Policy(HubConfig.model_validate(raw))
    assert policy.is_tool_ever_push_approved("technitium_dns_list") is True


# ---------------------------------------------------------------------------
# tool_arg_overrides
# ---------------------------------------------------------------------------


def _policy_with_arg_overrides(
    overrides: dict[str, dict[str, object]],
) -> Policy:
    """Build a Policy whose ironclaw identity has the given overrides."""
    import copy

    raw = copy.deepcopy(MINIMAL)
    raw["identities"]["ironclaw"]["tool_arg_overrides"] = overrides  # type: ignore[index]
    return Policy(HubConfig.model_validate(raw))


def test_tool_arg_overrides_absent_returns_none() -> None:
    """No overrides on the identity → accessor returns None."""
    policy = _policy()
    assert policy.tool_arg_overrides("ironclaw", "technitium_dns_list") is None


def test_tool_arg_overrides_exact_match_returns_dict() -> None:
    policy = _policy_with_arg_overrides(
        {"technitium_dns_list": {"limit": 5, "filter": ["A", "AAAA"]}}
    )
    got = policy.tool_arg_overrides("ironclaw", "technitium_dns_list")
    assert got == {"limit": 5, "filter": ["A", "AAAA"]}


def test_tool_arg_overrides_no_glob_match() -> None:
    """Override keys are exact tool names — globbing is intentionally
    not supported (security: ambiguity is a smell)."""
    policy = _policy_with_arg_overrides(
        {"technitium_dns_*": {"limit": 5}}  # this is meant to never fire
    )
    # Even though the key looks like a glob, lookup is exact: a tool
    # whose name happens to LITERALLY be "technitium_dns_*" would hit;
    # nothing else.
    assert policy.tool_arg_overrides("ironclaw", "technitium_dns_list") is None
    assert policy.tool_arg_overrides("ironclaw", "technitium_dns_*") == {"limit": 5}


def test_tool_arg_overrides_returned_dict_is_a_copy() -> None:
    """Caller may mutate the returned dict without affecting policy state."""
    policy = _policy_with_arg_overrides(
        {"technitium_dns_list": {"sources": ["a", "b"]}}
    )
    got = policy.tool_arg_overrides("ironclaw", "technitium_dns_list")
    assert got is not None
    got["sources"] = ["mutated"]
    again = policy.tool_arg_overrides("ironclaw", "technitium_dns_list")
    assert again == {"sources": ["a", "b"]}


def test_tool_arg_overrides_rejects_tool_not_in_allowed_tools() -> None:
    """An override for a tool the identity can't call would silently
    never fire — fail at load."""
    with pytest.raises(PolicyError, match="never fire"):
        _policy_with_arg_overrides(
            {"outline_get_doc": {"max_chars": 10000}}  # ironclaw only has technitium_*
        )


def test_tool_arg_overrides_accepts_glob_matching_tool() -> None:
    """If `allowed_tools` is "technitium_*", an override on a specific
    `technitium_dns_list` is valid — the override matches an allowed tool."""
    policy = _policy_with_arg_overrides(
        {"technitium_dns_list": {"limit": 5}}
    )
    assert policy.tool_arg_overrides("ironclaw", "technitium_dns_list") == {"limit": 5}
