"""Config placeholder expansion — one templating model for policy.yaml.

Several strings in ``policy.yaml`` vary per (identity, MCP) and were each
expanded ad-hoc at their own call site. This is the single shared expander used
by all of them:

- ``identities[*].secrets[*].path`` (stdio/container secret refs)
- ``mcps[*].auth.config.path_template`` (SecretBearer)
- ``mcps[*].secrets_to_env[*].path`` and ``audience_template`` (container)
- ``mcps[*].volumes_per_identity[*].volume_name_template`` (container)
- ``secret_backend.config.role_template`` (bao role name)

Supported placeholders: ``{identity}`` and ``{mcp}``. Anything else (a typo, or
``{aud}`` etc.) is a config error and raises, so it surfaces at load/dispatch
rather than silently producing a wrong path.
"""

from __future__ import annotations


def expand_template(template: str, *, identity: str, mcp: str) -> str:
    """Expand ``{identity}`` / ``{mcp}`` in ``template``.

    Literal strings (no placeholders) pass through unchanged. An unsupported
    placeholder or a malformed brace raises :class:`ValueError`.
    """
    try:
        return template.format(identity=identity, mcp=mcp)
    except (KeyError, IndexError, ValueError) as exc:
        raise ValueError(
            f"template {template!r} uses an unsupported placeholder ({exc}); "
            f"supported: {{identity}}, {{mcp}}"
        ) from exc
