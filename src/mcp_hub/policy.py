"""Hub configuration and policy loader.

The whole hub is driven by a single YAML file (``policy.yaml``). This
module:

- Parses + schema-validates the file via pydantic
- Catches policy errors at load time, not at runtime — bad globs,
  collisions, version mismatch, MCP-name underscores all fail fast
- Exposes typed accessors used by the hub server: which tools an
  identity may see, what HITL action a tool requires, etc.

Policy file shape (excerpt; full example in policy.example.yaml)::

    version: 1
    auth: { issuer, jwks_uri, audience_prefix, ... }
    secret_backend: { name: bao, config: { ... } }
    approver: { name: ntfy, config: { ... } }
    mcps:
      technitium:
        command: ["node", "/app/.../index.js"]
        secret_env_name: TECHNITIUM_TOKEN_FILE
    identities:
      ironclaw:
        aud: mcp-ironclaw
        uid_base: 1001
        allowed_tools: ["technitium_dns_*"]
        hitl:
          defaults: auto-approve
          overrides:
            technitium_dns_delete_record: push-approve
        secrets:
          technitium:
            path: secret/data/services/technitium/ironclaw
            field: api_token

HITL precedence rule (locked in by tests):

- Most-specific pattern wins (longest pattern, where ``*`` and other
  wildcards still count toward length). Ties broken by dict insertion
  order (which is YAML source order under PyYAML).
- If no override matches, ``defaults`` applies.
"""

from __future__ import annotations

import fnmatch
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class PolicyError(Exception):
    """Raised for any policy-load or schema validation failure."""


class HITLAction(StrEnum):
    AUTO_APPROVE = "auto-approve"
    PUSH_APPROVE = "push-approve"
    REJECT = "reject"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bind: str = "127.0.0.1:8443"
    hitl_webhook_path: str = "/hitl/ack"


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issuer: str
    jwks_uri: str
    audience_prefix: str
    # OIDC discovery URL — used by bao's JWT auth method, NOT by the hub.
    # Authentik publishes per-app discovery URLs even when issuer_mode=global,
    # so this can differ from `issuer`. The hub itself uses `jwks_uri` directly.
    oidc_discovery_url: str | None = None
    algorithms: list[str] = Field(default_factory=lambda: ["RS256"])
    clock_skew_s: int = 30
    cache_ttl_s: int = 600


class BackendChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    config: dict[str, Any] = Field(default_factory=dict)


class AuditConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sink: Literal["stderr"] = "stderr"
    hash_args_default: bool = True


class SecretRefModel(BaseModel):
    """YAML serialization of an interfaces.SecretRef."""

    model_config = ConfigDict(extra="forbid")
    path: str
    field: str


class MCPConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: list[str] = Field(min_length=1)
    secret_env_name: str
    uid_offset: int = 0
    extra_env: dict[str, str] = Field(default_factory=dict)


class HITLPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    defaults: HITLAction = HITLAction.AUTO_APPROVE
    overrides: dict[str, HITLAction] = Field(default_factory=dict)


class IdentityPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aud: str
    uid_base: int
    allowed_tools: list[str] = Field(min_length=1)
    hitl: HITLPolicy = Field(default_factory=HITLPolicy)
    secrets: dict[str, SecretRefModel]


class TokenRefresherPlugin(BaseModel):
    """One side (source or sink) of a refresher entry.

    ``type`` is the plugin lookup key (entry-point name in
    ``mcp_hub.token_sources`` / ``mcp_hub.token_sinks``, or a dotted-path
    import string for in-repo plugins). ``config`` is passed to the
    resolved class as ``**kwargs``; the class is responsible for its
    own kwarg validation.
    """

    model_config = ConfigDict(extra="forbid")
    type: str
    config: dict[str, Any] = Field(default_factory=dict)


class TokenRefresherConfig(BaseModel):
    """One refresher entry under ``token_refresh.<name>``."""

    model_config = ConfigDict(extra="forbid")
    source: TokenRefresherPlugin
    sink: TokenRefresherPlugin
    # Duration string in "unit=N" form ("minutes=10", "hours=1", "days=30",
    # "seconds=30"). Parsed to a timedelta in the factory.
    rotate_every: str
    safety_buffer: str = "seconds=30"
    initial_backoff: str = "seconds=5"
    max_backoff: str = "minutes=2"


class HubConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int
    server: ServerConfig = Field(default_factory=ServerConfig)
    auth: AuthConfig
    secret_backend: BackendChoice
    approver: BackendChoice
    audit: AuditConfig = Field(default_factory=AuditConfig)
    mcps: dict[str, MCPConfig] = Field(min_length=1)
    identities: dict[str, IdentityPolicy] = Field(min_length=1)
    # Optional. Empty / absent = no token rotation, the operator is
    # responsible for keeping any tokens-on-disk fresh. Production
    # policy MUST set this for fanout_jwt.
    token_refresh: dict[str, TokenRefresherConfig] = Field(default_factory=dict)

    @field_validator("version")
    @classmethod
    def _check_version(cls, v: int) -> int:
        if v != 1:
            raise ValueError(f"unsupported policy version: {v}")
        return v

    @field_validator("mcps")
    @classmethod
    def _check_mcp_names_no_underscore(
        cls, v: dict[str, MCPConfig]
    ) -> dict[str, MCPConfig]:
        # MCP names form the prefix in tool names like "technitium_dns_list".
        # Routing splits on the first `_` to recover the MCP name. If an MCP
        # name itself contained `_`, e.g. "paperless_gpt", a tool like
        # "paperless_gpt_search" would split as ["paperless", "gpt_search"]
        # and route nowhere (or worse, to a different MCP).
        for name in v:
            if "_" in name:
                raise ValueError(
                    f"MCP name {name!r} must not contain '_' "
                    f"(routing splits tool names on first '_'). "
                    f"Use '-' or join words, e.g. 'paperless-gpt' or 'paperlessgpt'."
                )
            if not name:
                raise ValueError("MCP name must be non-empty")
        return v


# ---------------------------------------------------------------------------
# Top-level Policy facade with cross-field validation + accessors
# ---------------------------------------------------------------------------


class Policy:
    """Validated hub policy with typed accessors."""

    def __init__(self, config: HubConfig) -> None:
        self._config = config
        self._validate_cross_field()

    @property
    def config(self) -> HubConfig:
        return self._config

    # -----------------------------------------------------------------------
    # Loading
    # -----------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError(f"cannot read policy file {path!r}: {exc}") from exc

        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyError(f"YAML parse error in {path!r}: {exc}") from exc

        if not isinstance(raw, dict):
            raise PolicyError(
                f"policy file {path!r} top level must be a mapping, got {type(raw).__name__}"
            )

        try:
            config = HubConfig.model_validate(raw)
        except ValidationError as exc:
            raise PolicyError(f"policy schema validation failed:\n{exc}") from exc

        return cls(config)

    # -----------------------------------------------------------------------
    # Cross-field invariants
    # -----------------------------------------------------------------------

    def _validate_cross_field(self) -> None:
        mcp_names = set(self._config.mcps)

        for identity_name, identity in self._config.identities.items():
            # Every identity must have a secret entry for every MCP it could
            # call. We enforce that secrets keys are a SUBSET of mcps —
            # extra entries are a config error (typo? leftover?).
            extra = set(identity.secrets) - mcp_names
            if extra:
                raise PolicyError(
                    f"identity {identity_name!r} has secrets for unknown MCPs: "
                    f"{sorted(extra)}; known: {sorted(mcp_names)}"
                )
            # Every allowed_tool glob must reference an MCP name as its
            # prefix-before-underscore (e.g. "technitium_*" or
            # "technitium_dns_delete_record"). Globs that don't start with
            # any known MCP name will never match anything — flag at load.
            for glob in identity.allowed_tools:
                prefix = glob.split("_", 1)[0]
                if prefix not in mcp_names:
                    raise PolicyError(
                        f"identity {identity_name!r}: allowed_tools entry "
                        f"{glob!r} doesn't start with any known MCP name "
                        f"(prefix {prefix!r}); known MCPs: {sorted(mcp_names)}"
                    )

    # -----------------------------------------------------------------------
    # Accessors
    # -----------------------------------------------------------------------

    def identity(self, name: str) -> IdentityPolicy:
        try:
            return self._config.identities[name]
        except KeyError as exc:
            raise PolicyError(f"unknown identity {name!r}") from exc

    def identity_for_audience(self, audience: str) -> str | None:
        """Return the identity name whose ``aud`` exactly matches, or None."""
        for name, identity in self._config.identities.items():
            if identity.aud == audience:
                return name
        return None

    def is_tool_allowed(self, identity_name: str, tool: str) -> bool:
        """True if any of the identity's globs matches ``tool``."""
        identity = self.identity(identity_name)
        return any(fnmatch.fnmatchcase(tool, glob) for glob in identity.allowed_tools)

    def filter_tools(self, identity_name: str, tools: list[str]) -> list[str]:
        """Return the subset of ``tools`` allowed for this identity."""
        identity = self.identity(identity_name)
        globs = identity.allowed_tools
        return [t for t in tools if any(fnmatch.fnmatchcase(t, g) for g in globs)]

    def hitl_decision(self, identity_name: str, tool: str) -> HITLAction:
        """Resolve the HITL action for ``identity`` calling ``tool``.

        Precedence (locked in by tests):

        1. Most-specific matching override pattern (longest pattern) wins
        2. Ties broken by dict insertion order (YAML source order)
        3. If no override matches, ``hitl.defaults`` applies
        """
        identity = self.identity(identity_name)
        # Iterate in insertion order so dict order is the tiebreak.
        matches = [
            (pattern, action)
            for pattern, action in identity.hitl.overrides.items()
            if fnmatch.fnmatchcase(tool, pattern)
        ]
        if not matches:
            return identity.hitl.defaults
        # Stable sort by descending pattern length: longest first; ties
        # preserve original (insertion) order.
        matches.sort(key=lambda pa: len(pa[0]), reverse=True)
        return matches[0][1]

    def mcp_name_for_tool(self, tool: str) -> str:
        """Return the MCP name that owns ``tool`` (its prefix before the first '_')."""
        return tool.split("_", 1)[0]
