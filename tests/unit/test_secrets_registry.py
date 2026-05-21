"""Tests for the SecretBackend plugin registry."""

from __future__ import annotations

import pytest

from mcp_hub.secrets.bao import BaoSecretBackend
from mcp_hub.secrets.env import EnvSecretBackend
from mcp_hub.secrets.file import FileSecretBackend
from mcp_hub.secrets.registry import SecretBackendNotFound, resolve_secret_backend


def test_resolves_builtins_by_name() -> None:
    assert resolve_secret_backend("env") is EnvSecretBackend
    assert resolve_secret_backend("file") is FileSecretBackend
    assert resolve_secret_backend("bao") is BaoSecretBackend


def test_dotted_path_fallback_for_in_repo_adapter() -> None:
    assert (
        resolve_secret_backend("mcp_hub.secrets.env.EnvSecretBackend")
        is EnvSecretBackend
    )


def test_unknown_bare_name_raises() -> None:
    with pytest.raises(SecretBackendNotFound):
        resolve_secret_backend("does-not-exist")


def test_empty_name_raises() -> None:
    with pytest.raises(SecretBackendNotFound):
        resolve_secret_backend("")


def test_dotted_path_to_non_class_raises() -> None:
    # env_var_name is a function, not a class.
    with pytest.raises(SecretBackendNotFound):
        resolve_secret_backend("mcp_hub.secrets.env.env_var_name")


def test_class_without_protocol_methods_raises() -> None:
    # pathlib.Path is a class but has no resolve()/close().
    with pytest.raises(SecretBackendNotFound):
        resolve_secret_backend("pathlib.Path")
