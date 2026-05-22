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
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


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
    """Inbound auth config. ``mode`` selects how callers are authenticated:

    - ``oidc`` (default): validate an inbound OIDC JWT against the issuer's JWKS.
      Requires ``issuer`` and an identity strategy — ``audience_prefix`` (the
      aud-suffix model) or ``identity_claim`` (sub / azp / client_id / custom).
      ``jwks_uri`` is optional; when omitted it's discovered from the issuer's
      ``/.well-known/openid-configuration``. ``audience`` (optional) adds an
      exact aud check. Works with Authentik / Keycloak / Auth0 / Zitadel / ...
    - ``static_token``: opaque bearer tokens → identities, from ``token_file``
      (YAML/JSON mapping ``identity: token``). No IdP. Requires ``token_file``.
    - ``trusted_proxy``: trust a fronting auth proxy that injects
      ``identity_header``; the proxy must also send the shared secret from
      ``shared_secret_file`` (header ``x-mcp-gateway-auth``). Requires both.

    ``jwt_passthrough``, ``secret_bearer`` with ``as_agent: true``, and
    ``container``-transport MCPs all need an inbound JWT and therefore
    ``mode: oidc`` — the factory rejects them otherwise.
    """

    model_config = ConfigDict(extra="forbid")
    mode: Literal["oidc", "static_token", "trusted_proxy"] = "oidc"

    # ── oidc (required when mode=oidc) ──
    issuer: str | None = None
    jwks_uri: str | None = None
    audience_prefix: str | None = None
    # OIDC discovery URL — used by bao's JWT auth method, NOT by the hub.
    # Authentik publishes per-app discovery URLs even when issuer_mode=global,
    # so this can differ from `issuer`. The hub itself uses `jwks_uri` directly.
    oidc_discovery_url: str | None = None
    # Identity extraction: default is the aud-suffix after audience_prefix
    # (audience-per-identity). Set identity_claim to instead read the identity
    # from a named claim (sub / azp / client_id / custom) — for IdPs that don't
    # mint a per-identity audience. `audience` (optional) adds an exact aud check.
    identity_claim: str | None = None
    audience: str | None = None
    algorithms: list[str] = Field(default_factory=lambda: ["RS256"])
    clock_skew_s: int = 30
    cache_ttl_s: int = 600

    # ── static_token (required when mode=static_token) ──
    token_file: str | None = None

    # ── trusted_proxy (required when mode=trusted_proxy) ──
    identity_header: str | None = None
    shared_secret_file: str | None = None

    @model_validator(mode="after")
    def _check_mode_fields(self) -> AuthConfig:
        required = {
            "oidc": ("issuer",),
            "static_token": ("token_file",),
            "trusted_proxy": ("identity_header", "shared_secret_file"),
        }
        missing = [f for f in required[self.mode] if getattr(self, f) is None]
        if missing:
            raise ValueError(f"auth.mode={self.mode!r} requires: {', '.join(missing)}")
        if (
            self.mode == "oidc"
            and self.audience_prefix is None
            and self.identity_claim is None
        ):
            raise ValueError(
                "auth.mode='oidc' requires an identity strategy: set "
                "audience_prefix or identity_claim"
            )
        # Reject fields belonging to a different mode (catch copy-paste/typos).
        # Only the None-defaulted fields are checked; the OIDC tuning knobs with
        # real defaults (algorithms/clock_skew_s/cache_ttl_s) are always benign.
        cross = {
            "oidc": ("token_file", "identity_header", "shared_secret_file"),
            "static_token": (
                "issuer", "jwks_uri", "audience_prefix", "oidc_discovery_url",
                "identity_claim", "audience", "identity_header", "shared_secret_file",
            ),
            "trusted_proxy": (
                "issuer", "jwks_uri", "audience_prefix", "oidc_discovery_url",
                "identity_claim", "audience", "token_file",
            ),
        }
        foreign = [f for f in cross[self.mode] if getattr(self, f) is not None]
        if foreign:
            raise ValueError(
                f"auth.mode={self.mode!r} does not use: {', '.join(foreign)}"
            )
        return self


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


class VolumeMount(BaseModel):
    """A persistent Docker volume mount for a container-transport MCP.

    For per-identity scope, ``volume_name_template`` MUST contain
    ``{identity}`` so each identity gets its own volume (otherwise all
    identities collide on a single shared volume — defeats the purpose).
    For shared scope, the placeholder is optional (a static name is fine
    since there's only one container).

    Volumes are auto-created by Docker on first mount; the orchestrator
    does NOT remove them on container teardown — they persist across
    spawn/evict cycles, which is the whole point. Operator removes
    manually if an identity is decommissioned.
    """

    model_config = ConfigDict(extra="forbid")
    container_path: str
    volume_name_template: str


class AuthStrategyConfig(BaseModel):
    """Discriminated config for an HTTP MCP's auth strategy.

    The ``type`` field selects which :mod:`mcp_hub.auth_strategies`
    impl the factory builds. ``config`` is passed to that impl as
    ``**kwargs``-shaped values (the factory adapts them).

    Built-in types:

    - ``secret_bearer`` (alias: ``bao_backed_bearer``) — config:
      ``path_template`` (str, required; e.g. ``"services/outline/{identity}"``),
      ``field`` (str, default ``"api_token"``), ``cache_ttl_s`` (float, default 30),
      ``as_agent`` (bool, default False). Resolves a per-identity secret from the
      configured ``secret_backend``. When ``as_agent`` is True, autonomous
      identities (``kind: autonomous``) authenticate to the secret store using
      their *own* inbound JWT (e.g. a bao role bound to ``aud=mcp-<identity>``)
      instead of the hub's deputy credentials — closing the confused-deputy gap
      so the store audits the agent. The injected downstream Bearer is still the
      per-agent token at ``path_template``; only the store-side auth principal
      changes. Delegated identities on the same MCP stay deputy.
    - ``jwt_passthrough`` — config: empty.
    - ``fanout_jwt`` — config: ``path`` (str, optional; default
      ``/etc/mcp-gateway/fanout_jwt``). Forwards the hub's own
      service-account JWT (audience ``mcp-fanout-svc``) as the upstream
      Bearer regardless of caller identity. Pair with ``scope: shared``
      container MCPs whose wrapper accepts ``OIDC_BOOT_AUDIENCE``.
      Per-identity HITL/audit still happens hub-side via the inbound
      caller JWT — only the upstream-facing call uses the hub JWT.
    - ``none`` — config: empty. Sends NO ``Authorization`` header to the
      upstream. For homelab-internal MCPs that don't require auth (e.g.
      HA's built-in MCP integration, which uses a URL-embedded token
      instead of a header). Hub-side HITL/audit still apply.
    """

    model_config = ConfigDict(extra="forbid")
    type: str
    config: dict[str, Any] = Field(default_factory=dict)


class MCPConfig(BaseModel):
    """One backend MCP entry.

    Three transports are supported, selected by ``transport``:

    - ``stdio`` (default): the historical pattern. Spawns subprocesses
      via :class:`mcp_fanout.Fanout`. Requires ``command`` and
      ``secret_env_name``. Slated for deprecation once Technitium migrates
      to ``container``.
    - ``http``: federates an external already-running Streamable-HTTP MCP
      via :class:`mcp_fanout.HttpFanout`. Requires ``url`` and ``auth``.
      Used for upstreams the hub doesn't manage (Outline, KitchenOwl).
    - ``container``: orchestrates wrapper containers on demand via
      :class:`mcp_fanout.ContainerFanout`. Requires ``image``. Per-spawn
      env injection (including bao-resolved secrets) lands in the
      container's process env and never on disk.

    Field-presence is validated per-transport — see :meth:`_check_transport_fields`.
    """

    model_config = ConfigDict(extra="forbid")
    transport: Literal["stdio", "http", "container"] = "stdio"

    # stdio fields (required when transport == "stdio")
    command: list[str] | None = Field(default=None)
    secret_env_name: str | None = None
    uid_offset: int = 0
    extra_env: dict[str, str] = Field(default_factory=dict)

    # http fields (required when transport == "http")
    url: str | None = None

    # container fields (required when transport == "container")
    image: str | None = None
    # "per-identity" → one container per identity (default; the per-user
    # isolation case, e.g., HEB).
    # "shared"       → one container regardless of caller (e.g., Technitium —
    #                  one DNS API token, used by everyone).
    scope: Literal["per-identity", "shared"] = "per-identity"
    idle_timeout_s: float = 1200.0     # 20 min
    spawn_timeout_s: float = 60.0
    eviction_interval_s: float = 60.0
    audience_template: str = "mcp-{identity}"
    # Host the hub uses to reach a spawned wrapper's published port. None ⇒
    # host.docker.internal (Docker Desktop / Linux Docker with host-gateway);
    # set for rootless / Podman / k8s. Container-transport only.
    container_host: str | None = None
    # env: pass-through env vars set on every spawned container of this MCP.
    # Static — not bao-resolved. For sensitive runtime values use secrets_to_env.
    env: dict[str, str] = Field(default_factory=dict)
    # secrets_to_env: ENV_VAR -> SecretRef(path, field). The orchestrator
    # resolves each ref via the SecretBackend at spawn time and injects the
    # resolved value as that env var. ``path`` may include ``{identity}``
    # which is formatted at spawn time. Token never lands on disk.
    secrets_to_env: dict[str, SecretRefModel] = Field(default_factory=dict)
    # volumes_per_identity: Docker named-volume mounts that persist across
    # container teardown/respawn. Use ONLY for MCPs that legitimately need
    # persistent session state beyond an env-injected token (e.g. HEB's
    # Playwright cookies + auth.json). Most MCPs leave this empty — tokens
    # flow via `secrets_to_env`, which is in-memory only.
    volumes_per_identity: list[VolumeMount] = Field(default_factory=list)

    # http + container shared field (required for both)
    auth: AuthStrategyConfig | None = None

    @field_validator("command")
    @classmethod
    def _check_command_nonempty_when_set(
        cls, v: list[str] | None
    ) -> list[str] | None:
        if v is not None and len(v) == 0:
            raise ValueError("command must be non-empty when set")
        return v

    @model_validator(mode="after")
    def _check_transport_fields(self) -> MCPConfig:
        if self.transport == "stdio":
            missing: list[str] = []
            if not self.command:
                missing.append("command")
            if not self.secret_env_name:
                missing.append("secret_env_name")
            if missing:
                raise ValueError(f"transport=stdio requires fields: {missing}")
            # Fields that belong to other transports must NOT be set here.
            for forbidden in ("url", "auth"):
                if getattr(self, forbidden) is not None:
                    raise ValueError(
                        f"transport=stdio: field {forbidden!r} is http-only"
                    )
            if self.image is not None:
                raise ValueError("transport=stdio: field 'image' is container-only")
            if self.secrets_to_env:
                raise ValueError(
                    "transport=stdio: field 'secrets_to_env' is container-only"
                )
            if self.env:
                raise ValueError(
                    "transport=stdio: use 'extra_env' instead of 'env'"
                )
            if self.container_host is not None:
                raise ValueError(
                    "transport=stdio: field 'container_host' is container-only"
                )
        elif self.transport == "http":
            missing_http: list[str] = []
            if self.url is None or not self.url:
                missing_http.append("url")
            if self.auth is None:
                missing_http.append("auth")
            if missing_http:
                raise ValueError(f"transport=http requires fields: {missing_http}")
            # stdio/container-only fields must NOT be set on an http entry
            if self.command is not None:
                raise ValueError("transport=http: field 'command' is stdio-only")
            if self.secret_env_name is not None:
                raise ValueError("transport=http: field 'secret_env_name' is stdio-only")
            if self.uid_offset != 0:
                raise ValueError("transport=http: field 'uid_offset' is stdio-only")
            if self.extra_env:
                raise ValueError("transport=http: field 'extra_env' is stdio-only")
            if self.image is not None:
                raise ValueError("transport=http: field 'image' is container-only")
            if self.env:
                raise ValueError("transport=http: field 'env' is container-only")
            if self.secrets_to_env:
                raise ValueError(
                    "transport=http: field 'secrets_to_env' is container-only"
                )
            if self.container_host is not None:
                raise ValueError(
                    "transport=http: field 'container_host' is container-only"
                )
            assert self.url is not None
            if not self.url.startswith(("http://", "https://")):
                raise ValueError(
                    f"transport=http: url must be http(s)://, got {self.url!r}"
                )
        else:  # transport == "container"
            missing_c: list[str] = []
            if not self.image:
                missing_c.append("image")
            if self.auth is None:
                missing_c.append("auth")
            if missing_c:
                raise ValueError(f"transport=container requires fields: {missing_c}")
            # stdio/http-only fields must NOT be set
            if self.command is not None:
                raise ValueError("transport=container: field 'command' is stdio-only")
            if self.secret_env_name is not None:
                raise ValueError(
                    "transport=container: field 'secret_env_name' is stdio-only"
                )
            if self.uid_offset != 0:
                raise ValueError(
                    "transport=container: field 'uid_offset' is stdio-only"
                )
            if self.extra_env:
                raise ValueError(
                    "transport=container: use 'env' instead of 'extra_env'"
                )
            if self.url is not None:
                raise ValueError("transport=container: field 'url' is http-only")
            if self.idle_timeout_s <= 0:
                raise ValueError("transport=container: idle_timeout_s must be > 0")
            if self.spawn_timeout_s <= 0:
                raise ValueError("transport=container: spawn_timeout_s must be > 0")
            # audience_template requirements depend on scope:
            # - per-identity: {identity} REQUIRED (each container is spawned
            #   for one identity; the per-call JWT must match its OIDC_AUDIENCE)
            # - shared: {identity} optional. The container is spawned once
            #   with whichever identity called first, but per-call JWTs
            #   from other identities won't match. Use auth: type=fanout_jwt
            #   so the hub forwards its own service-account JWT (audience
            #   mcp-fanout-svc) — accepted by the wrapper as OIDC_BOOT_AUDIENCE.
            if self.scope == "per-identity" and "{identity}" not in self.audience_template:
                raise ValueError(
                    f"transport=container, scope=per-identity: audience_template "
                    f"must contain {{identity}} placeholder, got: "
                    f"{self.audience_template!r}"
                )
            # volumes_per_identity: per-identity scope MUST have {identity}
            # in the volume name template; otherwise all identities collide
            # on a single shared volume (defeats the per-identity isolation
            # this transport exists to provide).
            if self.scope == "per-identity":
                for vm in self.volumes_per_identity:
                    if "{identity}" not in vm.volume_name_template:
                        raise ValueError(
                            f"transport=container, scope=per-identity: "
                            f"volumes_per_identity entry's volume_name_template "
                            f"must contain {{identity}}, got: "
                            f"{vm.volume_name_template!r}"
                        )
        # stdio + http transports reject volumes_per_identity (container-only).
        if self.transport != "container" and self.volumes_per_identity:
            raise ValueError(
                f"transport={self.transport}: field 'volumes_per_identity' is "
                f"container-only"
            )
        return self


class HITLPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    defaults: HITLAction = HITLAction.AUTO_APPROVE
    overrides: dict[str, HITLAction] = Field(default_factory=dict)


class IdentityPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aud: str
    uid_base: int
    # Identity CLASS — the delegated-vs-autonomous distinction:
    #   - "delegated": a human driving a tool (interactive, claude-code-dev).
    #     Reads secrets via the hub's deputy credentials downstream.
    #   - "autonomous": an agent acting on its own. On MCPs that opt in
    #     (auth.config.as_agent: true), authenticates to the secret store AS
    #     ITSELF using its inbound JWT, and gets its own per-agent token.
    # Defaults to delegated so existing identities keep current behavior.
    kind: Literal["delegated", "autonomous"] = "delegated"
    allowed_tools: list[str] = Field(min_length=1)
    hitl: HITLPolicy = Field(default_factory=HITLPolicy)
    # Per-MCP secret refs resolved at stdio/container spawn. Optional — http /
    # container MCPs that get their token via the auth strategy (`path_template`)
    # or `secrets_to_env` need no entry here. Each `path` may use the
    # `{identity}` / `{mcp}` placeholders (see mcp_hub.templating).
    secrets: dict[str, SecretRefModel] = Field(default_factory=dict)
    # Per-tool argument overrides. Hub stamps these into the call's
    # arguments dict at dispatch time (clobbers agent-supplied values),
    # so an identity can be constrained to a SUBSET of a tool's surface
    # without trusting the agent to self-restrict.
    #
    # Map shape: {exact_tool_name: {arg_name: forced_value}}.
    #
    # Canonical use case: per-identity `sources` on `index_search` so
    # alfred only sees Outline > HomeAssistant chunks, never recipes.
    # Glob patterns on tool names are NOT supported (use exact names)
    # — the override is a forcing function and ambiguity here is a
    # security smell.
    tool_arg_overrides: dict[str, dict[str, Any]] = Field(default_factory=dict)


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
    # Policy schema version (currently 1). Versioning policy: changes are
    # additive-only (new optional fields, new placeholders), so v1 stays valid;
    # a genuinely breaking change would bump this and the loader would gate on it.
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
            # Every tool name referenced by tool_arg_overrides must be
            # allowed by one of the identity's allowed_tools globs.
            # An override on a tool the identity can't call is a typo —
            # the override would silently never fire. Fail at load.
            for tool_name in identity.tool_arg_overrides:
                if not any(
                    fnmatch.fnmatchcase(tool_name, g) for g in identity.allowed_tools
                ):
                    raise PolicyError(
                        f"identity {identity_name!r}: tool_arg_overrides entry "
                        f"{tool_name!r} is not matched by any allowed_tools glob "
                        f"({identity.allowed_tools!r}) — the override would never fire."
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

    def tool_arg_overrides(
        self, identity_name: str, tool: str
    ) -> dict[str, Any] | None:
        """Return the per-identity forced args for ``tool``, or None.

        Exact tool-name match only (no glob). Callers should
        ``arguments.update(overrides)`` to clobber agent-supplied
        values — these are forced, not defaults.
        """
        identity = self.identity(identity_name)
        forced = identity.tool_arg_overrides.get(tool)
        if not forced:
            return None
        return dict(forced)

    def is_tool_ever_push_approved(self, tool: str) -> bool:
        """True if ANY identity's policy resolves ``tool`` to push-approve.

        Used by the registration phase in :class:`mcp_hub.server.Hub` to
        decide whether to inject a required ``justification`` parameter
        into the tool's input schema. Tools that are auto-approve for
        every identity don't need the parameter.
        """
        for identity_name in self._config.identities:
            if self.hitl_decision(identity_name, tool) == HITLAction.PUSH_APPROVE:
                return True
        return False
